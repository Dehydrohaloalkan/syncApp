using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SyncApp;

public sealed class GitService
{
    public async Task<byte[]> Run(string repo, params string[] args) => await RunInput(repo, null, args);

    public async Task<byte[]> RunInput(string repo, byte[]? input, params string[] args)
        => await RunInputWithIndex(repo, input, null, args);

    public async Task<byte[]> RunInputWithIndex(string repo, byte[]? input, string? indexFile, params string[] args)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = repo, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false };
        if (indexFile != null) start.Environment["GIT_INDEX_FILE"] = indexFile;
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Не удалось запустить git");
        using var output = new MemoryStream();
        var stdout = process.StandardOutput.BaseStream.CopyToAsync(output);
        var stderr = process.StandardError.ReadToEndAsync();
        if (input != null) { await process.StandardInput.BaseStream.WriteAsync(input); await process.StandardInput.BaseStream.FlushAsync(); }
        process.StandardInput.Close();
        await Task.WhenAll(stdout, stderr);
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new InvalidOperationException($"git {args[0]}: {await stderr}");
        return output.ToArray();
    }

    public async Task<string> Text(string repo, params string[] args) => Encoding.UTF8.GetString(await Run(repo, args)).Trim();

    public async Task EnsureBranch(string repo, string branch)
    {
        var top = await Text(repo, "rev-parse", "--show-toplevel");
        if (!Path.GetFullPath(top).Equals(Path.GetFullPath(repo), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) throw new InvalidOperationException("Укажите корень Git-репозитория");
        if (await Text(repo, "rev-parse", "--abbrev-ref", "HEAD") != branch) throw new InvalidOperationException($"Откройте ветку {branch}");
        foreach (var name in new[] { "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "BISECT_LOG", "rebase-merge", "rebase-apply", "sequencer" })
        {
            var path = await Text(repo, "rev-parse", "--git-path", name);
            var absolute = Path.IsPathRooted(path) ? path : Path.Combine(repo, path);
            if (File.Exists(absolute) || Directory.Exists(absolute)) throw new InvalidOperationException($"Git-операция {name} ещё активна");
        }
    }

    public async Task EnsureClean(string repo)
    {
        var state = await Run(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all");
        if (state.Length != 0) throw new InvalidOperationException("В репозитории есть незакоммиченные или неотслеживаемые файлы");
        await EnsureIndexFlags(repo);
    }

    // A shared junk clone is transport state. Never merge or rebase unrelated
    // local edits while refreshing it; callers get a fast-forward-only pull.
    public async Task SafePull(string repo)
    {
        await EnsureBranchRoot(repo);
        await EnsureClean(repo);
        await Run(repo, "pull", "--ff-only");
        await EnsureClean(repo);
    }

    public async Task SafePullPreservingWorktree(string repo)
    {
        await EnsureBranchRoot(repo);
        if ((await Run(repo, "diff", "--cached", "--name-only", "-z")).Length != 0)
            throw new InvalidOperationException("В junk уже есть staged-файлы");
        await EnsureIndexFlags(repo);
        foreach (var name in new[] { "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "BISECT_LOG", "rebase-merge", "rebase-apply", "sequencer" })
        {
            var path = await Text(repo, "rev-parse", "--git-path", name);
            var absolute = Path.IsPathRooted(path) ? path : Path.Combine(repo, path);
            if (File.Exists(absolute) || Directory.Exists(absolute)) throw new InvalidOperationException($"Git-операция {name} ещё активна");
        }
        await Run(repo, "pull", "--ff-only");
        await EnsureIndexFlags(repo);
    }

    private async Task EnsureBranchRoot(string repo)
    {
        var top = await Text(repo, "rev-parse", "--show-toplevel");
        if (!Path.GetFullPath(top).Equals(Path.GetFullPath(repo), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidOperationException("Укажите корень Git-репозитория junk");
        var branch = await Text(repo, "rev-parse", "--abbrev-ref", "HEAD");
        if (branch == "HEAD") throw new InvalidOperationException("Для junk нужна рабочая ветка");
    }

    public async Task EnsureWorktreeMatchesIndex(string repo)
    {
        var output = await Run(repo, "diff", "--name-only", "-z");
        if (output.Length != 0) throw new InvalidOperationException("Рабочие файлы отличаются от индекса Git");
        var untracked = await Run(repo, "ls-files", "--others", "--exclude-standard", "-z");
        if (untracked.Length != 0) throw new InvalidOperationException("Есть неотслеживаемые файлы");
        await EnsureIndexFlags(repo);
    }

    public async Task EnsureNoUnstagedOrUntracked(string repo)
    {
        if ((await Run(repo, "diff", "--name-only", "-z")).Length != 0)
            throw new InvalidOperationException("В junk есть локальные изменения вне staged SyncApp-объектов");
        if ((await Run(repo, "ls-files", "--others", "--exclude-standard", "-z")).Length != 0)
            throw new InvalidOperationException("В junk есть неотслеживаемые файлы вне SyncApp-передачи");
        await EnsureIndexFlags(repo);
    }

    private async Task EnsureIndexFlags(string repo)
    {
        foreach (var line in (await Run(repo, "ls-files", "-v", "-z")).Split((byte)0))
            if (line.Length > 0 && line[0] != (byte)'H') throw new InvalidOperationException("Git skip-worktree/assume-unchanged или другой скрытый флаг индекса не поддерживается");
    }

    private static List<(string Mode, string Id, string Path)> ParseTree(byte[] bytes, bool index)
    {
        var result = new List<(string Mode, string Id, string Path)>();
        foreach (var raw in bytes.AsSpan().ToArray().Split((byte)0))
        {
            if (raw.Length == 0) continue;
            var text = Encoding.UTF8.GetString(raw);
            var tab = text.IndexOf('\t');
            if (tab < 0) throw new InvalidDataException("Некорректный вывод Git");
            var fields = text[..tab].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 3) throw new InvalidDataException("Некорректное дерево Git");
            var mode = fields[0];
            var id = index ? fields[1] : fields[2];
            if (index && fields[2] != "0") throw new InvalidOperationException("Неразрешённые стадии индекса Git");
            var path = text[(tab + 1)..];
            ValidatePath(path);
            if (mode is not ("100644" or "100755")) throw new NotSupportedException($"Git-режим {mode} для {path} пока не поддерживается");
            result.Add((mode, id, path));
        }
        return result.OrderBy(e => e.Path, StringComparer.Ordinal).ToList();
    }

    public async Task<List<(string Mode, string Id, string Path)>> Entries(string repo, string revision)
        => await EntriesWithIndex(repo, revision, null);

    private async Task<List<(string Mode, string Id, string Path)>> EntriesWithIndex(string repo, string revision, string? indexFile)
    {
        var entries = revision == ":"
            ? ParseTree(await RunInputWithIndex(repo, null, indexFile, "ls-files", "--stage", "-z"), true)
            : ParseTree(await Run(repo, "ls-tree", "-r", "-z", "--full-tree", revision), false);
        var comparer = StringComparer.OrdinalIgnoreCase;
        if (entries.Select(e => e.Path).Distinct(comparer).Count() != entries.Count) throw new NotSupportedException("Пути различаются только регистром");
        return entries;
    }

    public async Task<string> Digest(string repo, string revision)
        => await DigestWithIndex(repo, revision, null);

    public async Task<string> DigestWithIndex(string repo, string revision, string? indexFile)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var e in await EntriesWithIndex(repo, revision, indexFile))
        {
            var blob = await Run(repo, "cat-file", "blob", e.Id);
            hash.AppendData(Encoding.UTF8.GetBytes(e.Path)); hash.AppendData(new byte[] { 0 });
            hash.AppendData(Encoding.ASCII.GetBytes(e.Mode)); hash.AppendData(new byte[] { 0 });
            hash.AppendData(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((long)blob.Length)));
            hash.AppendData(blob);
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    public async Task PreviewPatch(string repo, byte[] patch, string expectedDigest, string? workspaceRoot = null)
    {
        var index = await Text(repo, "rev-parse", "--git-path", "index");
        if (!Path.IsPathRooted(index)) index = Path.Combine(repo, index);
        using var workspace = PrivateWorkspace.Create(workspaceRoot);
        var temp = workspace.FilePath("index");
        File.Copy(index, temp);
        await RunInputWithIndex(repo, patch, temp, "apply", "--cached", "--binary", "-");
        if (await DigestWithIndex(repo, ":", temp) != expectedDigest) throw new InvalidDataException("Результат пакета не совпадает с заявленным деревом");
    }

    public static void ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith('/') || path.Contains('\\') || path.Any(ch => ch < 32 || "<>:\"|?*".Contains(ch))) throw new InvalidDataException("Недопустимый путь");
        foreach (var segment in path.Split('/'))
        {
            if (segment is "" or "." or ".." || segment.EndsWith(' ') || segment.EndsWith('.') || segment.Equals(".git", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Недопустимый путь: {path}");
            var stem = segment.Split('.')[0].ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" || (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && stem[3] is >= '1' and <= '9')) throw new InvalidDataException($"Имя несовместимо с Windows: {path}");
        }
    }

}

internal static class ByteSplit
{
    public static IEnumerable<byte[]> Split(this byte[] bytes, byte delimiter)
    {
        var start = 0;
        for (var i = 0; i < bytes.Length; i++)
            if (bytes[i] == delimiter) { yield return bytes[start..i]; start = i + 1; }
        if (start < bytes.Length) yield return bytes[start..];
    }
}
