using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net;

namespace SyncApp;

public sealed class SyncEngine(Registry registry, GitService git, CryptoService crypto,
    Func<OperationStage, Task>? checkpoint = null)
{
    private static readonly JsonSerializerOptions DescriptorJsonOptions = new(JsonConfig.Options)
    {
        NewLine = "\n"
    };

    // Keep encrypted objects below GitHub's per-file 100 MiB limit with room for
    // the signed age envelope and JSON/base64 expansion.
    public const int EncryptedFileLimit = 64 * 1024 * 1024;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Task Checkpoint(OperationStage stage) => checkpoint?.Invoke(stage) ?? Task.CompletedTask;
    private static readonly Regex FolderName = new("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$", RegexOptions.Compiled);

    private static string CheckedFolder(string folder)
    {
        if (!FolderName.IsMatch(folder) || folder is "." or ".." || folder.EndsWith('.')) throw new ArgumentException("Недопустимое имя папки проекта");
        return folder;
    }
    private static string ChannelDir(LocalProject p) => Path.Combine(p.JunkPath, p.Folder, "channels", p.ChannelId);
    private static string DescriptorFile(LocalProject p) => Path.Combine(p.JunkPath, p.Folder, "project.json");
    private static string BaselineDir(LocalProject p) => Path.Combine(ChannelDir(p), "baseline");
    private static string PackageDir(LocalProject p) => Path.Combine(ChannelDir(p), "packages", "personal-to-work");
    private static string ParseHex(string id) => Regex.IsMatch(id, "^[a-f0-9]{64}$") ? id : throw new InvalidDataException("Некорректный идентификатор");
    private static bool IsWithin(string path, string root)
    {
        var p = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return p.StartsWith(r, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }
    private void CheckLocations(string junk, string source)
    {
        RequireNoLinks(junk);
        RequireNoLinks(source);
        RequireNoLinks(registry.Root);
        if (IsWithin(source, junk) || IsWithin(junk, source) || IsWithin(source, registry.Root) || IsWithin(registry.Root, source) || IsWithin(junk, registry.Root) || IsWithin(registry.Root, junk)) throw new InvalidOperationException("Папки проекта, junk и данных приложения должны быть раздельны");
    }

    private static void RequireNoLinks(string path)
    {
        for (var current = Path.GetFullPath(path); current != null; current = Path.GetDirectoryName(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Пути SyncApp не должны содержать символические ссылки или junction: " + current);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    private static void RequireRegularFile(string path)
    {
        RequireNoLinks(path);
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.Directory) != 0)
            throw new InvalidDataException("Ожидался обычный файл передачи");
    }

    private static async Task<byte[]> ReadTransportFile(string path)
    {
        RequireRegularFile(path);
        var info = new FileInfo(path);
        if (!info.Exists || info.Length > EncryptedFileLimit) throw new InvalidDataException("Файл передачи отсутствует или превышает лимит 64 MiB");
        var bytes = await File.ReadAllBytesAsync(path);
        if (bytes.Length > EncryptedFileLimit) throw new InvalidDataException("Файл передачи превышает лимит 64 MiB");
        return bytes;
    }

    private async Task RequireRepositoryRoot(string path)
    {
        RequireNoLinks(path);
        RequireNoLinks(Path.Combine(path, ".git"));
        var actual = Encoding.UTF8.GetString(await git.Run(path, "rev-parse", "--show-toplevel")).TrimEnd('\r', '\n');
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(actual)), comparison))
            throw new InvalidOperationException("Выберите корень Git-репозитория: " + actual);
    }

    private async Task<LocalProject> CheckedProject(string id)
    {
        var project = await registry.Get(id);
        CheckLocations(project.JunkPath, project.RepoPath);
        RequireNoLinks(DescriptorFile(project));
        RequireNoLinks(BaselineDir(project));
        RequireNoLinks(PackageDir(project));
        await RequireRepositoryRoot(project.JunkPath);
        if (project.BaselineCommit != null) await RequireRepositoryRoot(project.RepoPath);
        if (project.Side == Side.Work) VerifyPinnedDescriptor(project, await Descriptor(project));
        return project;
    }
    public static string WorkKeyFingerprint(string recipient) => CryptoService.EncryptionFingerprint(recipient);

    private static async Task<ProjectDescriptor> Descriptor(LocalProject p)
    {
        var descriptor = ParseCanonicalDescriptor(await File.ReadAllBytesAsync(DescriptorFile(p)));
        if (descriptor.Version != 3 || descriptor.ProjectId != p.ProjectId || descriptor.ChannelId != p.ChannelId || descriptor.Epoch != p.Epoch) throw new InvalidDataException("Дескриптор старого или неподдерживаемого протокола");
        return descriptor;
    }

    private static ProjectDescriptor ParseCanonicalDescriptor(byte[] bytes)
    {
        var descriptor = JsonSerializer.Deserialize<ProjectDescriptor>(bytes, JsonConfig.Options)
            ?? throw new InvalidDataException("Дескриптор проекта пуст");
        var normalizedBytes = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\r\n", "\n", StringComparison.Ordinal));
        if (!normalizedBytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(descriptor, DescriptorJsonOptions)))
            throw new InvalidDataException("Дескриптор должен иметь точную каноническую схему SyncApp");
        return descriptor;
    }

    private async Task EnsureJunk(string path)
    {
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException("Junk-репозиторий не найден");
        await RequireRepositoryRoot(path);
    }

    public async Task<LocalProject> CreatePersonal(string folder, string junkPath, string repoPath, string passphrase)
    {
        await _gate.WaitAsync();
        try
        {
            CheckedFolder(folder); junkPath = Path.GetFullPath(junkPath); repoPath = Path.GetFullPath(repoPath);
            CheckLocations(junkPath, repoPath);
            await EnsureJunk(junkPath);
            await git.SafePull(junkPath);
            await RequireRepositoryRoot(repoPath);
            await git.EnsureClean(repoPath);
            var branch = await git.Text(repoPath, "rev-parse", "--abbrev-ref", "HEAD");
            if (branch == "HEAD") throw new InvalidOperationException("Нужна рабочая ветка");
            var head = await git.Text(repoPath, "rev-parse", "HEAD");
            var digest = await git.Digest(repoPath, head);
            var projectDir = Path.Combine(junkPath, folder);
            if (Directory.Exists(projectDir)) throw new InvalidOperationException("Такой каталог в junk уже существует");
            var keys = await crypto.Generate(registry.Root);
            var p = new LocalProject { Side = Side.Personal, Folder = folder, JunkPath = junkPath, RepoPath = repoPath, Branch = branch, BaselineCommit = head, BaselineVerified = true, LastPersonalCommit = head, CurrentDigest = digest };
            var descriptor = new ProjectDescriptor { PersonalRecipient = keys.AgeRecipient, PersonalSigningKey = keys.SigningPublicPem };
            p.ProjectId = descriptor.ProjectId; p.ChannelId = descriptor.ChannelId;
            p.PersonalRecipient = descriptor.PersonalRecipient; p.PersonalSigningKey = descriptor.PersonalSigningKey;
            p.KeysFile = Path.Combine(registry.Root, "keys", p.Id + ".key");
            CryptoService.SaveKeys(p.KeysFile, keys, passphrase);
            Directory.CreateDirectory(ChannelDir(p));
            await File.WriteAllTextAsync(DescriptorFile(p), JsonSerializer.Serialize(descriptor, DescriptorJsonOptions));
            await registry.Save(p);
            return p;
        }
        finally { _gate.Release(); }
    }

    public async Task<LocalProject> CreateWork(string folder, string junkPath, string repoPath, string passphrase, string personalFingerprint)
    {
        await _gate.WaitAsync();
        try
        {
            CheckedFolder(folder); junkPath = Path.GetFullPath(junkPath); repoPath = Path.GetFullPath(repoPath);
            CheckLocations(junkPath, repoPath);
            await EnsureJunk(junkPath);
            await git.SafePull(junkPath);
            await RequireRepositoryRoot(repoPath);
            var descriptorFile = Path.Combine(junkPath, folder, "project.json");
            RequireNoLinks(descriptorFile);
            var descriptor = ParseCanonicalDescriptor(await File.ReadAllBytesAsync(descriptorFile));
            if (descriptor.Version != 3 || descriptor.WorkRecipient != null || !Guid.TryParseExact(descriptor.ProjectId, "N", out _) || !Guid.TryParseExact(descriptor.ChannelId, "N", out _) || descriptor.Epoch != 1) throw new InvalidOperationException("Канал старого протокола, уже связан или не поддерживается");
            if (!string.Equals(CryptoService.PairFingerprint(descriptor.PersonalSigningKey, descriptor.PersonalRecipient), personalFingerprint, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Отпечаток личного устройства не совпал");
            await git.EnsureClean(repoPath);
            var branch = await git.Text(repoPath, "rev-parse", "--abbrev-ref", "HEAD");
            if (branch == "HEAD") throw new InvalidOperationException("Нужна рабочая ветка");
            var head = await git.Text(repoPath, "rev-parse", "HEAD");
            var digest = await git.Digest(repoPath, head);
            var keys = await crypto.GenerateAgeOnly(registry.Root);
            if (descriptor.WorkRecipient != null) throw new InvalidOperationException("Рабочий ключ уже подключён к этому каналу");
            var p = new LocalProject { Side = Side.Work, Folder = folder, JunkPath = junkPath, RepoPath = repoPath, Branch = branch, ProjectId = descriptor.ProjectId, ChannelId = descriptor.ChannelId, Epoch = descriptor.Epoch, BaselineCommit = head, BaselineVerified = false, LastWorkCommit = head, CurrentDigest = digest, PersonalRecipient = descriptor.PersonalRecipient, PersonalSigningKey = descriptor.PersonalSigningKey, WorkRecipient = keys.AgeRecipient };
            p.KeysFile = Path.Combine(registry.Root, "keys", p.Id + ".key");
            CryptoService.SaveKeys(p.KeysFile, keys, passphrase);
            await registry.Save(p);
            return p;
        }
        finally { _gate.Release(); }
    }

    private static void VerifyPinnedDescriptor(LocalProject p, ProjectDescriptor descriptor)
    {
        var workKeyMatches = p.Side == Side.Work
            ? descriptor.WorkRecipient == p.WorkRecipient || (!p.BaselineVerified && descriptor.WorkRecipient == null)
            : descriptor.WorkRecipient == p.WorkRecipient;
        if (descriptor.Version != 3 || descriptor.ProjectId != p.ProjectId || descriptor.ChannelId != p.ChannelId || descriptor.Epoch != p.Epoch
            || descriptor.PersonalRecipient != p.PersonalRecipient || descriptor.PersonalSigningKey != p.PersonalSigningKey
            || !workKeyMatches)
            throw new InvalidDataException("Публичный дескриптор расходится с закреплёнными ключами этого устройства");
    }

    private static string GitPath(string junkRoot, string path) => Path.GetRelativePath(junkRoot, path).Replace('\\', '/');

    private async Task WriteOwnedTransportFile(LocalProject p, string path, byte[] bytes)
    {
        var relative = GitPath(p.JunkPath, path);
        var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (File.Exists(path))
        {
            RequireRegularFile(path);
            var existing = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant();
            if (!p.OwnedTransportFiles.TryGetValue(relative, out var registered) || registered != existing)
                throw new InvalidDataException("Локальный файл передачи уже существует и не принадлежит этой операции");
            return;
        }
        p.OwnedTransportFiles[relative] = digest;
        await registry.Save(p); // Persist the exact encrypted object before writing it into junk.
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temp, bytes);
            File.Move(temp, path);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    public async Task<LocalProject> AttachWorkKey(string id, string recipient, string fingerprint)
    {
        await _gate.WaitAsync();
        try
        {
            var p = await CheckedProject(id);
            if (p.Side != Side.Personal) throw new InvalidOperationException("Рабочий ключ можно подключить только на личной стороне");
            if (!Regex.IsMatch(recipient, "^age1[0-9a-z]{58}$") || !string.Equals(CryptoService.EncryptionFingerprint(recipient), fingerprint, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Отпечаток рабочего age-ключа не совпал");
            var descriptor = await Descriptor(p);
            if ((p.WorkRecipient != null && p.WorkRecipient != recipient) || (descriptor.WorkRecipient != null && descriptor.WorkRecipient != recipient))
                throw new InvalidOperationException("Канал уже привязан к другому рабочему ключу");
            if (descriptor.PersonalRecipient != p.PersonalRecipient || descriptor.PersonalSigningKey != p.PersonalSigningKey)
                throw new InvalidDataException("Личный ключ в дескрипторе изменён");
            if (p.WorkRecipient == recipient && descriptor.WorkRecipient == recipient) return p;
            p.WorkRecipient = recipient;
            descriptor.WorkRecipient = recipient;
            var descriptorPath = DescriptorFile(p);
            var temp = descriptorPath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(descriptor, DescriptorJsonOptions));
                File.Move(temp, descriptorPath, true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            await registry.Save(p);
            return p;
        }
        finally { _gate.Release(); }
    }

    private async Task CreateBaselineJunkPackage(LocalProject p, SecretKeys keys)
    {
        if (p.Side != Side.Personal || p.WorkRecipient == null || p.BaselineCommit == null) return;
        var path = Path.Combine(BaselineDir(p), p.ChannelId + ".age");
        if (File.Exists(path))
        {
            RequireRegularFile(path);
            var relative = GitPath(p.JunkPath, path);
            var actual = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant();
            if (!p.OwnedTransportFiles.TryGetValue(relative, out var registered) || registered != actual)
                throw new InvalidDataException("Подписанный baseline уже существует, но не принадлежит этому устройству");
            return;
        }
        await git.EnsureBranch(p.RepoPath, p.Branch); await git.EnsureClean(p.RepoPath);
        var payload = new BaselinePayload { ProjectId = p.ProjectId, ChannelId = p.ChannelId, Epoch = p.Epoch, Digest = await git.Digest(p.RepoPath, p.BaselineCommit) };
        var encrypted = await crypto.Protect(JsonSerializer.SerializeToUtf8Bytes(payload, JsonConfig.Options), p.WorkRecipient, keys);
        if (encrypted.Length > EncryptedFileLimit) throw new NotSupportedException("Зашифрованный baseline больше лимита GitHub 64 MiB");
        await WriteOwnedTransportFile(p, path, encrypted);
    }

    private async Task VerifyRemoteBaseline(LocalProject p, SecretKeys keys)
    {
        if (p.Side != Side.Work || p.BaselineVerified) return;
        await git.EnsureBranch(p.RepoPath, p.Branch); await git.EnsureClean(p.RepoPath);
        var head = await git.Text(p.RepoPath, "rev-parse", "HEAD");
        if (head != p.BaselineCommit) throw new InvalidOperationException("Рабочая копия изменилась до проверки baseline; исходные файлы сохранены");
        var path = Path.Combine(BaselineDir(p), p.ChannelId + ".age");
        RequireRegularFile(path);
        if (!File.Exists(path)) throw new InvalidOperationException("В junk ещё нет подписанного baseline от личной стороны");
        var payload = JsonSerializer.Deserialize<BaselinePayload>(await crypto.Open(await ReadTransportFile(path), keys, p.PersonalSigningKey, workspaceRoot: registry.Root), JsonConfig.Options)
            ?? throw new InvalidDataException("Пустой baseline");
        var localDigest = await git.Digest(p.RepoPath, head);
        if (payload.Version != 3 || payload.ProjectId != p.ProjectId || payload.ChannelId != p.ChannelId || payload.Epoch != p.Epoch || payload.Digest != localDigest)
            throw new InvalidDataException("Рабочая копия не совпадает с подписанным baseline личного устройства");
        p.BaselineVerified = true;
        p.CurrentDigest = localDigest;
        await registry.Save(p);
    }

    private async Task<List<ChangePayload>> CreateOutboundChanges(LocalProject p, SecretKeys keys, int maxCommits)
    {
        var changes = new List<ChangePayload>();
        if (p.BaselineCommit == null) return changes;
        var personal = p.Side == Side.Personal;
        if (!personal || p.WorkRecipient == null) return changes;
        var commits = await CommitsAfter(p, p.LastPersonalCommit);
        if (p.PendingPersonalChanges.Count > commits.Count
            || p.PendingPersonalChanges.Where((pending, index) => commits[index] != pending.SourceCommit).Any())
            throw new InvalidOperationException("История личной ветки изменилась после подготовки пакетов");
        if (maxCommits > 0 && p.PendingPersonalChanges.Count > maxCommits)
            throw new InvalidOperationException($"Уже подготовлено пакетов: {p.PendingPersonalChanges.Count}. Укажите 0 или значение не меньше этой очереди.");
        var sourceCommits = p.PendingPersonalChanges.Select(x => x.SourceCommit).ToList();
        var additions = commits.Skip(sourceCommits.Count);
        if (maxCommits > 0) additions = additions.Take(maxCommits - sourceCommits.Count);
        sourceCommits.AddRange(additions);
        var previous = p.LastPersonalChangeId;
        for (var index = 0; index < sourceCommits.Count; index++)
        {
            var commit = sourceCommits[index];
            var change = await CreateChange(p, commit, Direction.PersonalToWork, previous);
            if (index < p.PendingPersonalChanges.Count)
            {
                if (change.ChangeId != p.PendingPersonalChanges[index].ChangeId)
                    throw new InvalidDataException("Подготовленный пакет не совпадает с сохранённой цепочкой");
            }
            else
            {
                p.PendingPersonalChanges.Add(new PreparedPersonalChange { SourceCommit = commit, ChangeId = change.ChangeId });
                await registry.Save(p);
            }
            await SavePackage(p, change, p.WorkRecipient!, keys, PackageDir(p));
            changes.Add(change); previous = change.ChangeId;
        }
        return changes;
    }

    private static void AdvanceOutboundCursor(LocalProject p, IReadOnlyList<ChangePayload> changes)
    {
        if (changes.Count == 0) return;
        if (p.Side == Side.Personal)
        {
            p.LastPersonalCommit = changes[^1].SourceCommit;
            p.LastPersonalChangeId = changes[^1].ChangeId;
            p.Published.AddRange(changes.Select(x => x.ChangeId));
            p.PendingPersonalChanges.Clear();
        }
        else throw new InvalidOperationException("Рабочая сторона не публикует пакеты");
    }

    private async Task<List<string>> GetEncryptedTransportFiles(LocalProject p)
    {
        var files = new List<string>();
        if (p.Side == Side.Personal)
        {
            var descriptorPath = DescriptorFile(p);
            if (File.Exists(descriptorPath))
            {
                var descriptor = await Descriptor(p);
                VerifyPinnedDescriptor(p, descriptor);
                files.Add(descriptorPath);
            }
        }
        var ownDirs = new[] { BaselineDir(p), PackageDir(p) };
        foreach (var entry in p.OwnedTransportFiles)
        {
            var file = Path.GetFullPath(Path.Combine(p.JunkPath, entry.Key.Replace('/', Path.DirectorySeparatorChar)));
            if (!ownDirs.Any(dir => string.Equals(Path.GetDirectoryName(file), Path.GetFullPath(dir), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)))
                throw new InvalidDataException("Реестр локальных пакетов указывает за пределы принадлежащего устройству направления");
            if (!File.Exists(file)) continue;
            RequireRegularFile(file);
            var name = Path.GetFileName(file);
            var parent = Path.GetDirectoryName(file)!;
            var validName = parent == Path.GetFullPath(BaselineDir(p)) ? name == p.ChannelId + ".age"
                : Regex.IsMatch(name, "^[a-f0-9]{64}\\.age$");
            var bytes = await File.ReadAllBytesAsync(file);
            var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (!validName || digest != entry.Value || bytes.Length > EncryptedFileLimit || !bytes.AsSpan().StartsWith("age-encryption.org/v1\n"u8))
                throw new InvalidDataException("Локальный транспортный объект изменён или не является зашифрованным age-пакетом");
            files.Add(file);
        }
        return files;
    }

    private async Task<int> CommitLocalTransportFiles(LocalProject p)
    {
        var files = await GetEncryptedTransportFiles(p);
        foreach (var file in files) await git.Run(p.JunkPath, "add", "--", GitPath(p.JunkPath, file));
        await git.EnsureNoUnstagedOrUntracked(p.JunkPath);
        var staged = await git.Run(p.JunkPath, "diff", "--cached", "--name-only", "-z");
        if (staged.Length == 0) return 0;
        var names = staged.Split((byte)0).Where(x => x.Length > 0).Select(Encoding.UTF8.GetString).ToHashSet(StringComparer.Ordinal);
        var known = files.Select(file => GitPath(p.JunkPath, file)).ToHashSet(StringComparer.Ordinal);
        if (!names.IsSubsetOf(known)) throw new InvalidOperationException("В junk уже есть staged-файлы вне SyncApp-передачи");
        p.PendingTransportCommit = new TransportCommitIntent
        {
            ParentCommit = await git.Text(p.JunkPath, "rev-parse", "HEAD"),
            Tree = await git.Text(p.JunkPath, "write-tree")
        };
        await registry.Save(p);
        await git.Run(p.JunkPath, "-c", "user.name=SyncApp", "-c", "user.email=syncapp@localhost", "commit", "-m", "SyncApp encrypted transport update");
        await CompletePendingTransportCommit(p);
        return names.Count;
    }

    private async Task CompletePendingTransportCommit(LocalProject p)
    {
        var intent = p.PendingTransportCommit;
        if (intent == null) return;
        var head = await git.Text(p.JunkPath, "rev-parse", "HEAD");
        if (head == intent.ParentCommit)
        {
            var staged = await git.Run(p.JunkPath, "diff", "--cached", "--name-only", "-z");
            if (staged.Length == 0)
            {
                p.PendingTransportCommit = null;
                await registry.Save(p);
                return;
            }
            if (await git.Text(p.JunkPath, "write-tree") != intent.Tree)
                throw new InvalidOperationException("Индекс junk изменён после прерывания транспортного коммита");
            await git.Run(p.JunkPath, "-c", "user.name=SyncApp", "-c", "user.email=syncapp@localhost", "commit", "-m", "SyncApp encrypted transport update");
            head = await git.Text(p.JunkPath, "rev-parse", "HEAD");
        }
        var parents = (await git.Text(p.JunkPath, "rev-list", "--parents", "-n", "1", head)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var tree = await git.Text(p.JunkPath, "rev-parse", head + "^{tree}");
        if (parents.Length != 2 || parents[1] != intent.ParentCommit || tree != intent.Tree)
            throw new InvalidOperationException("Не удалось восстановить незавершённый локальный транспортный коммит");
        await VerifyNeutralTransportCommit(p, head);
        if (!p.OwnedTransportCommits.Contains(head)) p.OwnedTransportCommits.Add(head);
        p.PendingTransportCommit = null;
        await registry.Save(p);
    }

    private async Task VerifyNeutralTransportCommit(LocalProject p, string commit)
    {
        var metadata = (await git.Text(p.JunkPath, "show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", commit)).Split('\0', 5);
        if (metadata.Length != 5 || metadata[0] != "SyncApp" || metadata[1] != "syncapp@localhost"
            || metadata[2] != "SyncApp" || metadata[3] != "syncapp@localhost"
            || metadata[4].TrimEnd('\r', '\n') != "SyncApp encrypted transport update")
            throw new InvalidOperationException("Локальная история junk содержит сторонний коммит или открытые метаданные");
        var descriptorPath = GitPath(p.JunkPath, DescriptorFile(p));
        var paths = (await git.Run(p.JunkPath, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", commit))
            .Split((byte)0).Where(x => x.Length > 0).Select(Encoding.UTF8.GetString).ToArray();
        if (paths.Length == 0) throw new InvalidOperationException("Пустой транспортный коммит не принадлежит SyncApp");
        foreach (var path in paths)
        {
            var blobInfo = Encoding.UTF8.GetString(await git.Run(p.JunkPath, "ls-tree", "-z", commit, "--", path));
            var mode = blobInfo.Split('\t')[0].Split(' ')[0];
            if (mode is not ("100644" or "100755")) throw new InvalidOperationException("Локальный коммит junk содержит ссылку или специальный файл");
            var bytes = await git.Run(p.JunkPath, "show", commit + ":" + path);
            if (path == descriptorPath)
            {
                var descriptor = ParseCanonicalDescriptor(bytes);
                if (descriptor.Version != 3 || descriptor.ProjectId != p.ProjectId || descriptor.ChannelId != p.ChannelId
                    || descriptor.Epoch != p.Epoch || descriptor.PersonalRecipient != p.PersonalRecipient
                    || descriptor.PersonalSigningKey != p.PersonalSigningKey
                    || (descriptor.WorkRecipient != null && descriptor.WorkRecipient != p.WorkRecipient))
                    throw new InvalidOperationException("Локальная история junk содержит неподтверждённый дескриптор");
                continue;
            }
            if (!p.OwnedTransportFiles.TryGetValue(path, out var expected)
                || bytes.Length > EncryptedFileLimit
                || !bytes.AsSpan().StartsWith("age-encryption.org/v1\n"u8)
                || Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() != expected)
                throw new InvalidOperationException("Локальная история junk содержит не принадлежащий приложению или незашифрованный файл");
        }
    }

    private async Task RecoverPendingTransportCommit(LocalProject p)
    {
        if (p.PendingTransportCommit == null) return;
        await CompletePendingTransportCommit(p);
    }

    private async Task VerifyLocalJunkCommits(LocalProject p)
    {
        var upstream = await git.Text(p.JunkPath, "rev-parse", "--verify", "@{upstream}");
        var mergeBase = await git.Text(p.JunkPath, "merge-base", upstream, "HEAD");
        var commits = (await git.Text(p.JunkPath, "rev-list", "--reverse", mergeBase + "..HEAD"))
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (commits.Length == 0) return;
        foreach (var commit in commits)
        {
            var parents = (await git.Text(p.JunkPath, "rev-list", "--parents", "-n", "1", commit)).Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parents.Length != 2) throw new InvalidOperationException("Локальная история junk содержит неподдерживаемый merge-коммит");
            if (!p.OwnedTransportCommits.Contains(commit))
                throw new InvalidOperationException("Локальная история junk содержит сторонний или не подтверждённый коммит");
            await VerifyNeutralTransportCommit(p, commit);
        }
    }

    private async Task SafePullWithPendingTransport(LocalProject p)
    {
        var known = (await GetEncryptedTransportFiles(p)).Select(x => GitPath(p.JunkPath, x)).ToHashSet(StringComparer.Ordinal);
        async Task ValidatePendingPaths()
        {
            var modified = (await git.Run(p.JunkPath, "diff", "--name-only", "-z")).Split((byte)0).Where(x => x.Length > 0).Select(Encoding.UTF8.GetString);
            var untracked = (await git.Run(p.JunkPath, "ls-files", "--others", "--exclude-standard", "-z")).Split((byte)0).Where(x => x.Length > 0).Select(Encoding.UTF8.GetString);
            if (modified.Concat(untracked).Any(path => !known.Contains(path)))
                throw new InvalidOperationException("В junk есть изменения вне зашифрованной SyncApp-передачи");
        }
        await ValidatePendingPaths();
        // Git itself preserves non-conflicting local transport files and refuses
        // to overwrite a conflicting descriptor/package. No stash or reset is used.
        await git.SafePullPreservingWorktree(p.JunkPath);
        await ValidatePendingPaths();
    }

    // Personal writes encrypted transport. Work can only fast-forward-pull and
    // verify it; no Work-side operation mutates the shared GitHub repository.
    public async Task<JunkSyncResult> SyncJunk(string id, string passphrase, bool push, int maxCommits = 0)
    {
        await _gate.WaitAsync();
        try
        {
            var p = await CheckedProject(id);
            if (p.Session != null) throw new InvalidOperationException("Сначала завершите текущую операцию");
            if (p.Side == Side.Work && push) throw new InvalidOperationException("Рабочая сторона доступна для чтения; GitHub может публиковать только личная сторона");
            var keys = CryptoService.LoadKeys(p.KeysFile, passphrase);
            if (p.Side == Side.Work)
            {
                await git.SafePull(p.JunkPath);
                VerifyPinnedDescriptor(p, await Descriptor(p));
                await VerifyRemoteBaseline(p, keys);
                var incoming = PackageDir(p);
                var count = Directory.Exists(incoming) ? Directory.EnumerateFiles(incoming, "*.age").Count() : 0;
                return new JunkSyncResult { PulledPackages = count, Pushed = false };
            }

            await RecoverPendingTransportCommit(p);
            // A previous app commit may already be ahead of the remote. Validate
            // its provenance before adding another operation to that history.
            await VerifyLocalJunkCommits(p);
            await SafePullWithPendingTransport(p);
            await CreateBaselineJunkPackage(p, keys);
            if (p.WorkRecipient == null) await git.EnsureClean(p.RepoPath);
            var changes = await CreateOutboundChanges(p, keys, maxCommits);
            var committedFiles = await CommitLocalTransportFiles(p);
            if (changes.Count > 0 && !push)
            {
                // Keep the cursor at the last published commit. A later explicit
                // push regenerates identical IDs and reuses these local packages.
            }
            if (push)
            {
                await VerifyLocalJunkCommits(p);
                await git.Run(p.JunkPath, "push");
                AdvanceOutboundCursor(p, changes);
                await registry.Save(p);
            }
            await registry.Save(p);
            return new JunkSyncResult { PreparedChanges = changes.Count, CommittedFiles = committedFiles, Pushed = push };
        }
        finally { _gate.Release(); }
    }

    private async Task<List<string>> CommitsAfter(LocalProject p, string? from)
    {
        await git.EnsureBranch(p.RepoPath, p.Branch); await git.EnsureClean(p.RepoPath);
        if (from == null) throw new InvalidOperationException("Нет начальной точки синхронизации");
        var head = await git.Text(p.RepoPath, "rev-parse", "HEAD");
        if (head == from) return [];
        var ancestor = await git.Text(p.RepoPath, "merge-base", from, head);
        if (ancestor != from) throw new InvalidOperationException("История ветки была переписана");
        var lines = (await git.Text(p.RepoPath, "rev-list", "--reverse", from + ".." + head)).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var commit in lines)
        {
            var parents = (await git.Text(p.RepoPath, "rev-list", "--parents", "-n", "1", commit)).Split(' ');
            if (parents.Length != 2) throw new NotSupportedException("Merge-коммиты пока не поддерживаются");
        }
        return lines.ToList();
    }

    private async Task<ChangePayload> CreateChange(LocalProject p, string commit, Direction direction, string? previous)
    {
        var parent = await git.Text(p.RepoPath, "rev-parse", commit + "^");
        var sourceMessage = await git.Text(p.RepoPath, "show", "-s", "--format=%B", commit);
        var patch = await git.Run(p.RepoPath, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", parent, commit, "--");
        var changeId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(p.ProjectId + ":" + p.ChannelId + ":" + p.Epoch + ":" + direction + ":" + commit))).ToLowerInvariant();
        return new ChangePayload { ProjectId = p.ProjectId, ChannelId = p.ChannelId, Epoch = p.Epoch, ChangeId = changeId, Direction = direction, PreviousChangeId = previous, SourceCommit = commit, ParentCommit = parent, Message = sourceMessage, BaseDigest = await git.Digest(p.RepoPath, parent), ResultDigest = await git.Digest(p.RepoPath, commit), PatchBase64 = Convert.ToBase64String(patch) };
    }

    private static void CheckPayload(LocalProject p, ChangePayload change, Direction direction)
    {
        if (change.Version != 3 || change.ProjectId != p.ProjectId || change.ChannelId != p.ChannelId || change.Epoch != p.Epoch || change.Direction != direction || change.ChangeId.Length != 64 || !Regex.IsMatch(change.ChangeId, "^[a-f0-9]{64}$")) throw new InvalidDataException("Пакет другого канала или версии");
    }

    private async Task<string> SavePackage(LocalProject p, ChangePayload change, string recipient, SecretKeys keys, string folder)
    {
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, change.ChangeId + ".age");
        if (File.Exists(path))
        {
            RequireRegularFile(path);
            var relative = GitPath(p.JunkPath, path);
            var actual = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant();
            if (!p.OwnedTransportFiles.TryGetValue(relative, out var registered) || registered != actual)
                throw new InvalidDataException("Пакет уже существует, но не принадлежит этой операции");
        }
        else
        {
            var bytes = await crypto.Protect(JsonSerializer.SerializeToUtf8Bytes(change, JsonConfig.Options), recipient, keys);
            if (bytes.Length > EncryptedFileLimit) throw new NotSupportedException("Зашифрованный пакет больше лимита GitHub 64 MiB");
            await WriteOwnedTransportFile(p, path, bytes);
        }
        return path;
    }

    public async Task<IReadOnlyList<ChangePayload>> Inbox(string id, string passphrase)
    {
        var p = await CheckedProject(id);
        if (p.Side != Side.Work || !p.BaselineVerified) throw new InvalidOperationException("Входящие доступны только на рабочей стороне после проверки baseline");
        var keys = CryptoService.LoadKeys(p.KeysFile, passphrase);
        var folder = PackageDir(p);
        if (!Directory.Exists(folder)) return [];
        var signer = p.PersonalSigningKey;
        var direction = Direction.PersonalToWork;
        var list = new List<ChangePayload>();
        foreach (var file in Directory.EnumerateFiles(folder, "*.age"))
        {
            RequireRegularFile(file);
            var change = JsonSerializer.Deserialize<ChangePayload>(await crypto.Open(await ReadTransportFile(file), keys, signer, workspaceRoot: registry.Root), JsonConfig.Options) ?? throw new InvalidDataException("Пустой пакет");
            CheckPayload(p, change, direction);
            if (Path.GetFileNameWithoutExtension(file) != change.ChangeId) throw new InvalidDataException("Имя пакета не совпадает с ChangeId");
            list.Add(change);
        }
        return list;
    }

    public async Task<ApplySession> Apply(string id, string changeId, string passphrase)
    {
        await _gate.WaitAsync();
        try
        {
            var p = await CheckedProject(id);
            if (p.Side != Side.Work || !p.BaselineVerified || p.BaselineCommit == null) throw new InvalidOperationException("Рабочий baseline ещё не проверен");
            await git.EnsureBranch(p.RepoPath, p.Branch);
            await RecoverPendingSession(p, passphrase);
            var session = p.Session;
            if (session == null) await git.EnsureClean(p.RepoPath);
            else
            {
                if (await git.Text(p.RepoPath, "rev-parse", "HEAD") != session.OriginalHead) throw new InvalidOperationException("HEAD изменился во время сессии");
                await git.EnsureWorktreeMatchesIndex(p.RepoPath);
                var current = await git.Digest(p.RepoPath, ":");
                if (current != session.ExpectedDigest) throw new InvalidOperationException("Индекс Git изменён вне приложения");
            }
            var direction = Direction.PersonalToWork;
            var folder = PackageDir(p);
            var file = Path.Combine(folder, ParseHex(changeId) + ".age");
            RequireRegularFile(file);
            var keys = CryptoService.LoadKeys(p.KeysFile, passphrase);
            var signer = p.PersonalSigningKey;
            var change = JsonSerializer.Deserialize<ChangePayload>(await crypto.Open(await ReadTransportFile(file), keys, signer, workspaceRoot: registry.Root), JsonConfig.Options) ?? throw new InvalidDataException("Пустой пакет");
            CheckPayload(p, change, direction);
            if (change.ChangeId != changeId) throw new InvalidDataException("Идентификатор пакета неверен");
            if (p.Applied.Contains(changeId) || session?.ChangeIds.Contains(changeId) == true) throw new InvalidOperationException("Этот пакет уже применён");
            var previous = session?.ChangeIds.LastOrDefault() ?? p.LastPersonalChangeId;
            if (change.PreviousChangeId != previous) throw new InvalidOperationException("Предыдущий пакет ещё не принят или цепочка расходится");
            var currentDigest = session?.ExpectedDigest ?? await git.Digest(p.RepoPath, "HEAD");
            if (session == null)
            {
                var expectedHead = p.LastWorkCommit;
                if (await git.Text(p.RepoPath, "rev-parse", "HEAD") != expectedHead) throw new InvalidOperationException("Ветка содержит свои коммиты после согласованной точки");
            }
            if (change.BaseDigest != currentDigest) throw new InvalidOperationException("Исходный код отличается от ожидаемой базы");
            var patch = Convert.FromBase64String(change.PatchBase64);
            await git.RunInput(p.RepoPath, patch, "apply", "--check", "--index", "--binary", "-");
            await git.PreviewPatch(p.RepoPath, patch, change.ResultDigest, registry.Root);
            if (session == null)
            {
                session = new ApplySession { OriginalHead = await git.Text(p.RepoPath, "rev-parse", "HEAD"), ExpectedDigest = currentDigest, Direction = direction.ToString() };
                p.Session = session;
            }
            session.PendingChangeId = changeId; session.PendingResultDigest = change.ResultDigest;
            await registry.Save(p);
            await Checkpoint(OperationStage.ApplyJournalSaved);
            await git.RunInput(p.RepoPath, patch, "apply", "--index", "--binary", "-");
            await Checkpoint(OperationStage.ApplyFilesWritten);
            await git.EnsureWorktreeMatchesIndex(p.RepoPath);
            if (await git.Digest(p.RepoPath, ":") != change.ResultDigest) throw new InvalidDataException("Патч применился, но итоговое дерево не совпало");
            session.ChangeIds.Add(changeId); session.ExpectedDigest = change.ResultDigest;
            session.PendingChangeId = null; session.PendingResultDigest = null;
            await registry.Save(p);
            return session;
        }
        finally { _gate.Release(); }
    }

    public async Task<CommitMap> Confirm(string id, string passphrase)
    {
        await _gate.WaitAsync();
        try
        {
            var p = await CheckedProject(id);
            await RecoverPendingSession(p, passphrase);
            return await ConfirmCore(p, passphrase);
        }
        finally { _gate.Release(); }
    }

    private async Task<CommitMap> ConfirmCore(LocalProject p, string passphrase)
    {
        // Validate unlock even when this is an idempotent retry of a completed confirmation.
        _ = CryptoService.LoadKeys(p.KeysFile, passphrase);
        if (p.Side != Side.Work || !p.BaselineVerified) throw new InvalidOperationException("Подтверждать входящие пакеты можно только на рабочей стороне");
        await git.EnsureBranch(p.RepoPath, p.Branch); await git.EnsureClean(p.RepoPath);
        var head = await git.Text(p.RepoPath, "rev-parse", "HEAD");
        if (p.Session == null)
        {
            var last = p.Maps.LastOrDefault();
            if (last != null && last.TargetCommit == head && await git.Digest(p.RepoPath, head) == last.ResultDigest)
                return last;
            throw new InvalidOperationException("Нет активной сессии");
        }
        var session = p.Session ?? throw new InvalidOperationException("Нет активной сессии");
        if (session.PendingChangeId != null) throw new InvalidOperationException("Применение пакета не завершилось");
        if (session.ChangeIds.Count == 0) throw new InvalidOperationException("В сессии нет применённых пакетов");
        var parents = (await git.Text(p.RepoPath, "rev-list", "--parents", "-n", "1", head)).Split(' ');
        if (parents.Length != 2 || parents[1] != session.OriginalHead) throw new InvalidOperationException("Нужен один новый обычный коммит поверх исходного HEAD");
        if (await git.Digest(p.RepoPath, head) != session.ExpectedDigest) throw new InvalidOperationException("Код ручного коммита отличается от применённых изменений");
        var map = new CommitMap { ChangeIds = [.. session.ChangeIds], TargetCommit = head, ResultDigest = session.ExpectedDigest };
        p.Maps.Add(map); p.Applied.AddRange(session.ChangeIds); p.CurrentDigest = session.ExpectedDigest;
        p.LastWorkCommit = head;
        p.LastPersonalChangeId = session.ChangeIds[^1];
        p.Session = null;
        await registry.Save(p);
        await Checkpoint(OperationStage.ConfirmationCommitted);
        return map;
    }

    private async Task RecoverPendingSession(LocalProject p, string passphrase)
    {
        var session = p.Session;
        if (session?.PendingChangeId == null) return;
        await git.EnsureBranch(p.RepoPath, p.Branch);
        var direction = Direction.PersonalToWork;
        if (session.Direction != direction.ToString()) throw new InvalidDataException("Неверное направление сессии");
        var folder = PackageDir(p);
        var keys = CryptoService.LoadKeys(p.KeysFile, passphrase);
        var signer = p.PersonalSigningKey;
        var bytes = await crypto.Open(await ReadTransportFile(Path.Combine(folder, ParseHex(session.PendingChangeId) + ".age")),
            keys, signer, workspaceRoot: registry.Root);
        var change = JsonSerializer.Deserialize<ChangePayload>(bytes, JsonConfig.Options) ?? throw new InvalidDataException("Пустой pending-пакет");
        CheckPayload(p, change, direction);
        var previous = session.ChangeIds.LastOrDefault() ?? p.LastPersonalChangeId;
        if (change.ChangeId != session.PendingChangeId || change.ResultDigest != session.PendingResultDigest
            || change.BaseDigest != session.ExpectedDigest || change.PreviousChangeId != previous
            || session.ChangeIds.Contains(change.ChangeId) || p.Applied.Contains(change.ChangeId))
            throw new InvalidDataException("Журнал применения не соответствует проверенному пакету");
        var head = await git.Text(p.RepoPath, "rev-parse", "HEAD");
        string current;
        if (head == session.OriginalHead)
        {
            await git.EnsureWorktreeMatchesIndex(p.RepoPath);
            current = await git.Digest(p.RepoPath, ":");
        }
        else
        {
            await git.EnsureClean(p.RepoPath);
            var parents = (await git.Text(p.RepoPath, "rev-list", "--parents", "-n", "1", head)).Split(' ');
            if (parents.Length != 2 || parents[1] != session.OriginalHead)
                throw new InvalidOperationException("После сбоя появились дополнительные коммиты; файлы сохранены");
            current = await git.Digest(p.RepoPath, head);
            if (current != change.ResultDigest) throw new InvalidOperationException("Ручной коммит не совпал с pending-результатом; файлы сохранены");
        }
        if (current == change.ResultDigest)
        {
            session.ChangeIds.Add(change.ChangeId);
            session.ExpectedDigest = current;
        }
        else if (current != session.ExpectedDigest)
            throw new InvalidOperationException("Состояние после сбоя изменено пользователем; файлы сохранены");
        session.PendingChangeId = null; session.PendingResultDigest = null;
        if (session.ChangeIds.Count == 0) p.Session = null;
        await registry.Save(p);
    }

    public async Task<LocalProject> Recover(string id, string passphrase)
    {
        await _gate.WaitAsync();
        try
        {
            var p = await CheckedProject(id);
            var keys = CryptoService.LoadKeys(p.KeysFile, passphrase);
            await RecoverPendingSession(p, passphrase);
            if (p.Session != null)
            {
                await git.EnsureBranch(p.RepoPath, p.Branch);
                if (await git.Text(p.RepoPath, "rev-parse", "HEAD") != p.Session.OriginalHead)
                    await ConfirmCore(p, passphrase);
                else
                {
                    await git.EnsureWorktreeMatchesIndex(p.RepoPath);
                    if (await git.Digest(p.RepoPath, ":") != p.Session.ExpectedDigest)
                        throw new InvalidOperationException("Накопленная группа изменена пользователем; файлы сохранены");
                }
            }
            return p;
        }
        finally { _gate.Release(); }
    }
}
