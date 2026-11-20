using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SyncApp;

var tests = new (string Name, Func<Task> Run)[]
{
    ("archive has tracked bytes and modes, independent history has same digest", ArchiveAndIndependentHistory),
    ("personal baseline is encrypted in junk and verified read-only on work", InitialSnapshotAcrossTwoJunkClones),
    ("personal changes reach work; manual apply and confirm write no junk objects", PersonalChangesApplyReadOnly),
    ("personal can publish the next chain without a work acknowledgement", PersonalCanPublishWithoutWorkAcknowledgement),
    ("failed personal push retries after restart without duplicate package or cursor advance", PushFailureCanRetry),
    ("failed transport pre-commit recovers exact staged tree", TransportCommitIntentRecoversAfterRestart),
    ("untrusted local junk commit is never published", ForeignLocalJunkCommitCannotBePushed),
    ("prepared packages cannot follow rewritten source history", PreparedChainRejectsSourceRewrite),
    ("work rejects a changed pinned descriptor after pull", ChangedDescriptorIsRejected),
    ("work rejects duplicate JSON descriptor fields", DuplicateDescriptorFieldIsRejected),
    ("work accepts canonical LF descriptor", () => WorkSupportsDescriptorLineEndings(autocrlf: false)),
    ("work accepts canonical descriptor under autocrlf", () => WorkSupportsDescriptorLineEndings(autocrlf: true)),
    ("empty foreign junk commit is never published", EmptyForeignJunkCommitCannotBePushed),
    ("owned .age symlink is rejected before staging", AgeSymlinkIsRejected),
    ("staged unrelated junk changes remain untouched and block sync", StagedUnrelatedJunkBlocksSync),
    ("fast-forward refusal preserves exact pending ciphertext and cursor", PullRefusalPreservesPendingCiphertext),
    ("mismatched prepared baseline is rejected without changing work source", MismatchedBaselineIsRejected),
    ("out-of-order and duplicate packets, wrong manual W are rejected", OutOfOrderDuplicateAndWrongCommit),
    ("work registration does not leave local junk changes", WorkRegistrationDoesNotDirtyJunk),
    ("tampered personal age recipient is rejected at pairing", TamperedRecipientIsRejected),
    ("symlink alias into junk is rejected", LocationAliasIsRejected),
    ("work-repo subdirectory is rejected", WorkSubdirectoryIsRejected),
    ("apply recovers before and after file writes", ApplyCheckpointRecovery),
    ("pending accumulated changes recover after manual commit", PendingManualCommitRecovery),
    ("pending recovery refuses wrong manual result", PendingRecoveryPreservesChanges),
    ("confirmation retry does not duplicate local map or write to junk", ConfirmationCheckpointRecovery),
    ("private scratch ignores OS temp and cleans up", PrivateScratchIsolation),
    ("dirty worktree and staged changes block clean operations", DirtyRepositoryIsBlocked),
    ("branch switch and merge in progress are blocked", BranchAndMergeAreBlocked),
    ("hidden Git index flags cannot hide local changes", HiddenIndexFlagsAreBlocked),
    ("rebase directories and sequencer block application", RebaseAndSequencerAreBlocked),
    ("case-insensitive path collisions are rejected on WSL", CaseCollisionIsBlocked),
    ("unsafe archive paths are rejected", UnsafePathsAreRejected),
    ("legacy commented age identity opens reference CLI age-v1 ciphertext", LegacyAgeCliIdentityAndCiphertext),
    ("large encrypted package roundtrips and rejects wrong signer", CryptoRoundtripAndSigner)
};

var failures = 0;
foreach (var (name, run) in tests)
{
    try
    {
        await run();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception error)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {name}: {error}");
    }
}
return failures == 0 ? 0 : 1;

static async Task ArchiveAndIndependentHistory()
{
    using var workspace = new TestWorkspace();
    var work = await workspace.NewRepository("work");
    var personal = await workspace.NewRepository("personal");
    Directory.CreateDirectory(Path.Combine(work, "папка с пробелом"));
    var code = "папка с пробелом/код.txt";
    await File.WriteAllTextAsync(Path.Combine(work, code), "строка\r\nдругая\r\n", Encoding.UTF8);
    await File.WriteAllBytesAsync(Path.Combine(work, "binary.bin"), [0, 1, 2, 0, 255]);
    await File.WriteAllTextAsync(Path.Combine(work, "run.sh"), "#!/bin/sh\nexit 0\n");
    await Git(work, "add", "--", ".");
    await Git(work, "update-index", "--chmod=+x", "run.sh");
    await Git(work, "commit", "-m", "work baseline");

    var git = new GitService();
    var archive = await ReadTrackedFiles(git, work, "HEAD");
    Equal(3, archive.Count, "archive tracked file count");
    Equal("100755", archive.Single(f => f.Path == "run.sh").Mode, "executable mode");
    Check(new byte[] { 0, 1, 2, 0, 255 }.AsSpan().SequenceEqual(archive.Single(f => f.Path == "binary.bin").Bytes), "binary bytes");
    var sourceCodeBytes = await File.ReadAllBytesAsync(Path.Combine(work, code));
    Check(sourceCodeBytes.AsSpan().SequenceEqual(archive.Single(f => f.Path == code).Bytes), "Unicode path and CRLF bytes");

    foreach (var entry in archive)
    {
        var target = Path.Combine(personal, entry.Path);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        await File.WriteAllBytesAsync(target, entry.Bytes);
        if (entry.Mode == "100755") await Git(personal, "add", "--chmod=+x", "--", entry.Path);
        else await Git(personal, "add", "--", entry.Path);
    }
    await Git(personal, "commit", "-m", "independent start");
    var workCommit = (await Git(work, "rev-parse", "HEAD")).Trim();
    var personalCommit = (await Git(personal, "rev-parse", "HEAD")).Trim();
    Check(workCommit != personalCommit, "histories should have distinct commit IDs");
    Equal(await git.Digest(work, "HEAD"), await git.Digest(personal, "HEAD"), "canonical digest");
}

static async Task InitialSnapshotAcrossTwoJunkClones()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = workspace.PathFor("personal-source");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "hello world.txt"), "hello\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "work history is private");

    var (personal, work, _, _) = await ConnectedProjects(workspace, bare, personalJunk, personalRepo, workRepo);
    Check(personal.BaselineCommit != null && work.BaselineVerified, "prepared source baseline was not established on both devices");
    var personalHead = (await Git(personalRepo, "rev-parse", "HEAD")).Trim();
    var workHead = (await Git(workRepo, "rev-parse", "HEAD")).Trim();
    Check(personalHead != workHead, "independent source repositories unexpectedly share history");
    Equal(await new GitService().Digest(workRepo, "HEAD"), await new GitService().Digest(personalRepo, "HEAD"), "prepared baseline canonical digest");
    var transportDir = Path.Combine(personal.JunkPath, personal.Folder, "channels", personal.ChannelId);
    var encryptedObjects = Directory.GetFiles(transportDir, "*.age", SearchOption.AllDirectories);
    Check(encryptedObjects.Length > 0, "encrypted baseline object was not committed to junk");
    Check(encryptedObjects.All(file => File.ReadAllBytes(file).AsSpan().StartsWith("age-encryption.org/v1\n"u8)), "baseline transport contains a plaintext object");
    Equal("", await Git(work.JunkPath, "status", "--porcelain=v1"), "read-only baseline verification dirtied Work junk");
    var receiptDir = Path.Combine(transportDir, "receipts");
    Check(!Directory.Exists(receiptDir) || Directory.GetFiles(receiptDir, "*.age", SearchOption.AllDirectories).Length == 0, "unexpected receipt was published");
    await AssertTransportBlobsDoNotContain(bare, "hello world.txt", "work history is private", "hello\n");
}

static async Task PersonalChangesApplyReadOnly()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = workspace.PathFor("personal-source");
    var workRepo = await workspace.NewRepository("work-source");
    await Git(workRepo, "checkout", "-b", "WORK_BRANCH_SECRET_49ab");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "code.txt"), "base\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "original work baseline");
    var (personal, work, personalRegistry, workRegistry) = await ConnectedProjects(workspace, bare, personalJunk, personalRepo, workRepo);
    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await Git(personalRepo, "config", "user.name", "SyncApp Test");
    await Git(personalRepo, "config", "user.email", "syncapp-test@example.invalid");

    await File.WriteAllTextAsync(Path.Combine(personalRepo, "code.txt"), "base\nA\n");
    await Git(personalRepo, "add", "code.txt");
    await Git(personalRepo, "commit", "-m", "personal A");
    await File.WriteAllTextAsync(Path.Combine(personalRepo, "private-path-93f7.txt"), "CONFIDENTIAL_VALUE_48ab\0binary\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "PERSONAL_COMMIT_SECRET_83cd");
    var personalSync = await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);
    Equal(2, personalSync.PreparedChanges, "two personal packages prepared");
    Equal(2, personalSync.CommittedFiles, "two encrypted package files committed");

    var remoteHead = (await Git(bare, "rev-parse", "refs/heads/main")).Trim();
    var workHeadBefore = (await Git(work.JunkPath, "rev-parse", "HEAD")).Trim();
    var workSync = await workEngine.SyncJunk(work.Id, "test passphrase", push: false);
    Equal(2, workSync.PulledPackages, "Work pull count");
    Check(!workSync.Pushed && workSync.CommittedFiles == 0, "Work wrote a transport commit");
    var workJunkHead = (await Git(work.JunkPath, "rev-parse", "HEAD")).Trim();
    Equal(remoteHead, workJunkHead, "Work junk did not stop at the remote pull commit");
    Check(workJunkHead != workHeadBefore, "Work did not fast-forward to personal packages");
    Equal((await Git(work.JunkPath, "rev-parse", "HEAD^{tree}")).Trim(), (await Git(work.JunkPath, "write-tree")).Trim(), "Work sync left junk index different from pulled HEAD");
    Equal("", await Git(work.JunkPath, "status", "--porcelain=v1"), "Work sync dirtied junk");

    var inbound = OrderChanges(await workEngine.Inbox(work.Id, "test passphrase"));
    Equal(2, inbound.Count, "work inbox count");
    var first = await workEngine.Apply(work.Id, inbound[0].ChangeId, "test passphrase");
    Equal(1, first.ChangeIds.Count, "first apply session count");
    var restartedWorkEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    var second = await restartedWorkEngine.Apply(work.Id, inbound[1].ChangeId, "test passphrase");
    Equal(2, second.ChangeIds.Count, "session persisted across host restart");
    Equal("base\n", await Git(workRepo, "show", "HEAD:code.txt"), "work source HEAD changed before manual commit");
    await Git(workRepo, "commit", "-m", "manual work commit for A+B");
    var map = await restartedWorkEngine.Confirm(work.Id, "test passphrase");
    Equal(2, map.ChangeIds.Count, "both personal changes mapped to manual work commit");
    Equal(await new GitService().Digest(personalRepo, "HEAD"), await new GitService().Digest(workRepo, "HEAD"), "A+B result digest");
    Equal(workJunkHead, (await Git(work.JunkPath, "rev-parse", "HEAD")).Trim(), "manual source commit or Confirm changed Work junk HEAD");
    Equal("", await Git(work.JunkPath, "status", "--porcelain=v1"), "manual source commit dirtied Work junk");
    var channelDir = Path.Combine(work.JunkPath, work.Folder, "channels", work.ChannelId);
    var receiptDir = Path.Combine(channelDir, "receipts");
    var outboundDir = Path.Combine(channelDir, "packages", "work-to-personal");
    Check(!Directory.Exists(receiptDir) || Directory.GetFiles(receiptDir, "*.age", SearchOption.AllDirectories).Length == 0, "Work created a junk receipt");
    Check(!Directory.Exists(outboundDir) || Directory.GetFiles(outboundDir, "*.age", SearchOption.AllDirectories).Length == 0, "Work created an outbound package");
    var prePushHook = Path.Combine((await Git(work.JunkPath, "rev-parse", "--absolute-git-dir")).Trim(), "hooks", "pre-push");
    var pushMarker = workspace.PathFor("work-push-was-invoked");
    await File.WriteAllTextAsync(prePushHook, "#!/bin/sh\nprintf invoked > '" + pushMarker + "'\n");
    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(prePushHook, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    await Throws(() => restartedWorkEngine.SyncJunk(work.Id, "test passphrase", push: true), "Work push is forbidden");
    Check(!File.Exists(pushMarker), "forbidden Work sync attempted Git push");
    Equal(workJunkHead, (await Git(work.JunkPath, "rev-parse", "HEAD")).Trim(), "forbidden Work push changed junk HEAD");
    await AssertTransportBlobsDoNotContain(bare, "WORK_BRANCH_SECRET_49ab", "PERSONAL_BRANCH_SECRET_9bc1", "code.txt", "original work baseline", "private-path-93f7.txt", "CONFIDENTIAL_VALUE_48ab", "PERSONAL_COMMIT_SECRET_83cd");
}

static async Task PersonalCanPublishWithoutWorkAcknowledgement()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "code.txt"), "base\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var engine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await File.AppendAllTextAsync(Path.Combine(personal.RepoPath, "code.txt"), "first\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "first independent change");
    Equal(1, (await engine.SyncJunk(personal.Id, "test passphrase", push: true)).PreparedChanges, "first chain package count");
    await File.AppendAllTextAsync(Path.Combine(personal.RepoPath, "code.txt"), "second\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "second independent change without ACK");
    Equal(1, (await engine.SyncJunk(personal.Id, "test passphrase", push: true)).PreparedChanges, "second personal chain was blocked awaiting work ACK");
}

static async Task PushFailureCanRetry()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = workspace.PathFor("personal-source");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "work baseline");
    var (personal, work, personalRegistry, workRegistry) = await ConnectedProjects(workspace, bare, personalJunk, personalRepo, workRepo);
    var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    await File.WriteAllTextAsync(Path.Combine(personalRepo, "retry.txt"), "retry payload\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "retry source commit");
    var cursorBefore = (await personalRegistry.Get(personal.Id)).LastPersonalCommit;
    var hook = Path.Combine(bare, "hooks", "pre-receive");
    await File.WriteAllTextAsync(hook, "#!/bin/sh\nexit 1\n");
    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(hook, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    await Throws(() => personalEngine.SyncJunk(personal.Id, "test passphrase", push: true), "rejected Git push");
    Equal(cursorBefore, (await personalRegistry.Get(personal.Id)).LastPersonalCommit, "failed push advanced personal commit cursor");
    var packageDir = Path.Combine(personalJunk, personal.Folder, "channels", personal.ChannelId, "packages", "personal-to-work");
    Equal(1, Directory.GetFiles(packageDir, "*.age").Length, "failed push did not leave one retryable ciphertext package");
    var commitsBeforeRetry = (await Git(personalJunk, "rev-list", "--count", "main")).Trim();

    File.Delete(hook);
    var restarted = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await restarted.SyncJunk(personal.Id, "test passphrase", push: true);
    Equal(1, Directory.GetFiles(packageDir, "*.age").Length, "retry duplicated encrypted package");
    Equal(commitsBeforeRetry, (await Git(personalJunk, "rev-list", "--count", "main")).Trim(), "retry created a duplicate local transport commit");
    Check((await personalRegistry.Get(personal.Id)).LastPersonalCommit != cursorBefore, "successful retry did not advance personal commit cursor");
    await workEngine.SyncJunk(work.Id, "test passphrase", push: false);
    Equal(1, (await workEngine.Inbox(work.Id, "test passphrase")).Count, "successful retry did not reach the other clone");
}

static async Task TransportCommitIntentRecoversAfterRestart()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var engine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await File.WriteAllTextAsync(Path.Combine(personal.RepoPath, "recovery.txt"), "queued encrypted change\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "queued change");

    var gitDir = (await Git(personalJunk, "rev-parse", "--absolute-git-dir")).Trim();
    var hook = Path.Combine(gitDir, "hooks", "pre-commit");
    await File.WriteAllTextAsync(hook, "#!/bin/sh\nexit 1\n");
    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(hook, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    var headBefore = (await Git(personalJunk, "rev-parse", "HEAD")).Trim();
    var commitCountBefore = int.Parse((await Git(personalJunk, "rev-list", "--count", "main")).Trim());
    await Throws(() => engine.SyncJunk(personal.Id, "test passphrase", push: true), "pre-commit hook failure after transport intent saved");
    var pending = await personalRegistry.Get(personal.Id);
    Check(pending.PendingTransportCommit != null, "interrupted transport intent was not durable");
    var pendingTree = (await Git(personalJunk, "write-tree")).Trim();
    Equal(pending.PendingTransportCommit!.Tree, pendingTree, "staged transport tree differs from durable intent");
    Check((await Git(personalJunk, "diff", "--cached", "--name-only")).Contains(".age"), "encrypted files were not left staged for exact recovery");

    File.Delete(hook);
    var restarted = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    var result = await restarted.SyncJunk(personal.Id, "test passphrase", push: true);
    Check(result.Pushed, "recovered transport commit was not pushed");
    Equal(commitCountBefore + 1, int.Parse((await Git(personalJunk, "rev-list", "--count", "main")).Trim()), "recovery duplicated transport commit");
    Check((await personalRegistry.Get(personal.Id)).PendingTransportCommit == null, "recovery retained stale transport intent");
    Check((await personalRegistry.Get(personal.Id)).LastPersonalCommit != null, "recovery did not advance source cursor after successful push");
    Equal((await Git(bare, "rev-parse", "refs/heads/main")).Trim(), (await Git(personalJunk, "rev-parse", "HEAD")).Trim(), "recovered commit did not reach local bare remote");
    Equal(headBefore, pending.PendingTransportCommit?.ParentCommit, "intent parent was not captured before commit attempt");
}

static async Task ForeignLocalJunkCommitCannotBePushed()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "work baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var engine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await File.WriteAllTextAsync(Path.Combine(personal.RepoPath, "source-change.txt"), "encrypted source payload\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "source change");

    var marker = "JUNK_PLAINTEXT_LEAK_73d9";
    await File.WriteAllTextAsync(Path.Combine(personalJunk, "notes.txt"), marker);
    await Git(personalJunk, "add", "notes.txt");
    await Git(personalJunk, "commit", "-m", "private junk note");
    var publishedHead = (await Git(bare, "rev-parse", "refs/heads/main")).Trim();

    await Throws(() => engine.SyncJunk(personal.Id, "test passphrase", push: true), "untrusted local junk commit");
    Equal(publishedHead, (await Git(bare, "rev-parse", "refs/heads/main")).Trim(), "untrusted local junk commit was pushed");
    await AssertTransportBlobsDoNotContain(bare, "notes.txt", marker, "private junk note");
}

static async Task PreparedChainRejectsSourceRewrite()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "code.txt"), "base\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var engine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await File.AppendAllTextAsync(Path.Combine(personal.RepoPath, "code.txt"), "A\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "A");
    var originalSecond = (await Git(personal.RepoPath, "rev-parse", "HEAD")).Trim();
    await File.AppendAllTextAsync(Path.Combine(personal.RepoPath, "code.txt"), "B\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "B original");
    await engine.SyncJunk(personal.Id, "test passphrase", push: false);
    var packageDir = Path.Combine(personalJunk, personal.Folder, "channels", personal.ChannelId, "packages", "personal-to-work");
    var packageFiles = Directory.GetFiles(packageDir, "*.age").Order().ToArray();
    Equal(2, packageFiles.Length, "preparation did not create both queued package files");
    var localTransportHead = (await Git(personalJunk, "rev-parse", "HEAD")).Trim();
    var remoteHead = (await Git(bare, "rev-parse", "refs/heads/main")).Trim();

    await Git(personal.RepoPath, "reset", "--hard", originalSecond);
    await File.AppendAllTextAsync(Path.Combine(personal.RepoPath, "code.txt"), "B rewritten\n");
    await Git(personal.RepoPath, "add", ".");
    await Git(personal.RepoPath, "commit", "-m", "B rewritten");
    await Throws(() => engine.SyncJunk(personal.Id, "test passphrase", push: true), "rewritten prepared source chain");
    Equal(remoteHead, (await Git(bare, "rev-parse", "refs/heads/main")).Trim(), "rewritten source history was published");
    Equal(localTransportHead, (await Git(personalJunk, "rev-parse", "HEAD")).Trim(), "rewrite changed the already prepared transport commit");
    Check(packageFiles.SequenceEqual(Directory.GetFiles(packageDir, "*.age").Order()), "rewrite replaced prepared ciphertext files");
}

static async Task ChangedDescriptorIsRejected()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, work, _, workRegistry) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var descriptorPath = Path.Combine(personalJunk, personal.Folder, "project.json");
    var descriptor = JsonSerializer.Deserialize<ProjectDescriptor>(await File.ReadAllTextAsync(descriptorPath), JsonConfig.Options)!;
    descriptor.WorkRecipient = "age1tamperedrecipient";
    await File.WriteAllTextAsync(descriptorPath, JsonSerializer.Serialize(descriptor, JsonConfig.Options));
    await Git(personalJunk, "add", "--", Path.GetRelativePath(personalJunk, descriptorPath));
    await Git(personalJunk, "commit", "-m", "tampered descriptor");
    await Git(personalJunk, "push");

    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    await ThrowsData(() => workEngine.SyncJunk(work.Id, "test passphrase", push: false), "changed pinned descriptor");
    Equal("", await Git(work.JunkPath, "status", "--porcelain=v1"), "descriptor refusal dirtied Work junk index or worktree");
    Equal(0, (await workRegistry.Get(work.Id)).Maps.Count, "descriptor refusal changed Work source maps");
}

static async Task DuplicateDescriptorFieldIsRejected()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, work, _, workRegistry) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var descriptorPath = Path.Combine(personalJunk, personal.Folder, "project.json");
    var descriptorJson = await File.ReadAllTextAsync(descriptorPath);
    var marker = "\"workRecipient\":";
    var propertyOffset = descriptorJson.IndexOf(marker, StringComparison.Ordinal);
    Check(propertyOffset >= 0, "descriptor is missing work recipient property");
    var propertyEnd = descriptorJson.IndexOf(',', propertyOffset);
    if (propertyEnd < 0) propertyEnd = descriptorJson.IndexOf('\n', propertyOffset);
    Check(propertyEnd > propertyOffset, "could not locate descriptor property boundary");
    var property = descriptorJson[propertyOffset..propertyEnd];
    descriptorJson = descriptorJson.Insert(propertyEnd, ",\n  " + property);
    await File.WriteAllTextAsync(descriptorPath, descriptorJson);
    await Git(personalJunk, "add", "--", Path.GetRelativePath(personalJunk, descriptorPath));
    await Git(personalJunk, "commit", "-m", "duplicate descriptor field");
    await Git(personalJunk, "push");
    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    await ThrowsData(() => workEngine.SyncJunk(work.Id, "test passphrase", push: false), "duplicate known JSON descriptor property");
}

static async Task WorkSupportsDescriptorLineEndings(bool autocrlf)
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (_, work, _, _) = await ConnectedProjects(workspace, bare, personalJunk,
        workspace.PathFor("personal-source"), workRepo, workAutocrlf: autocrlf);
    var descriptor = await File.ReadAllTextAsync(Path.Combine(work.JunkPath, work.Folder, "project.json"));
    var expectedLineEnding = autocrlf ? "\r\n" : "\n";
    Check(descriptor.Contains(expectedLineEnding, StringComparison.Ordinal), "fixture did not materialize the expected descriptor line ending");
    if (!autocrlf)
    {
        Check(!descriptor.Contains("\r\n", StringComparison.Ordinal), "LF fixture contains CRLF");
    }
    Check(work.BaselineVerified, "descriptor line ending blocked work baseline verification");
}

static async Task EmptyForeignJunkCommitCannotBePushed()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var secretMessage = "JUNK_COMMIT_MESSAGE_LEAK_aa71";
    await Git(personalJunk, "commit", "--allow-empty", "-m", secretMessage);
    var remoteHead = (await Git(bare, "rev-parse", "refs/heads/main")).Trim();
    await Throws(() => new SyncEngine(personalRegistry, new GitService(), new CryptoService()).SyncJunk(personal.Id, "test passphrase", push: true), "empty foreign junk commit");
    Equal(remoteHead, (await Git(bare, "rev-parse", "refs/heads/main")).Trim(), "empty foreign commit was pushed");
    await AssertTransportBlobsDoNotContain(bare, secretMessage);
}

static async Task AgeSymlinkIsRejected()
{
    if (OperatingSystem.IsWindows()) return;
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var relative = Path.Combine(personal.Folder, "channels", personal.ChannelId, "packages", "personal-to-work", new string('a', 64) + ".age");
    var linkPath = Path.Combine(personalJunk, relative);
    Directory.CreateDirectory(Path.GetDirectoryName(linkPath)!);
    var external = workspace.PathFor("external.age");
    var bytes = Encoding.ASCII.GetBytes("age-encryption.org/v1\nfixture ciphertext");
    await File.WriteAllBytesAsync(external, bytes);
    File.CreateSymbolicLink(linkPath, external);

    var current = await personalRegistry.Get(personal.Id);
    current.OwnedTransportFiles[relative.Replace('\\', '/')] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    await personalRegistry.Save(current);
    var previousHead = (await Git(personalJunk, "rev-parse", "HEAD")).Trim();
    await Throws(() => new SyncEngine(personalRegistry, new GitService(), new CryptoService()).SyncJunk(personal.Id, "test passphrase", push: true), "age symlink in transport manifest");
    Equal(previousHead, (await Git(personalJunk, "rev-parse", "HEAD")).Trim(), "age symlink was committed before rejection");
    Check(File.Exists(linkPath) && (File.GetAttributes(linkPath) & FileAttributes.ReparsePoint) != 0, "rejected symlink was removed");
    Equal("", (await Git(personalJunk, "diff", "--cached", "--name-only")).Trim(), "rejected symlink was staged");
    Equal("", (await Git(personalJunk, "ls-tree", "-r", "--name-only", "HEAD", "--", relative.Replace('\\', '/'))).Trim(), "Git committed a symlink as an encrypted file");
    Equal((await Git(bare, "rev-parse", "refs/heads/main")).Trim(), (await Git(personalJunk, "rev-parse", "origin/main")).Trim(), "remote moved during symlink rejection");
}

static async Task StagedUnrelatedJunkBlocksSync()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "work baseline");
    var (personal, _, personalRegistry, _) = await ConnectedProjects(workspace, bare, personalJunk, workspace.PathFor("personal-source"), workRepo);
    var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    var unrelated = Path.Combine(personalJunk, "unrelated.txt");
    await File.WriteAllTextAsync(unrelated, "keep this staged edit\n");
    await Git(personalJunk, "add", "unrelated.txt");
    await Throws(() => personalEngine.SyncJunk(personal.Id, "test passphrase", push: true), "unrelated staged junk change");
    Equal("A  unrelated.txt\n", await Git(personalJunk, "status", "--porcelain=v1"), "sync changed unrelated staged state");
    Equal("keep this staged edit\n", await File.ReadAllTextAsync(unrelated), "sync changed unrelated file contents");
    Equal("", (await Git(personalJunk, "diff", "--cached", "--name-only", "--", personal.Folder)).Trim(), "sync staged project transport while unrelated junk was dirty");
}

static async Task PullRefusalPreservesPendingCiphertext()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = workspace.PathFor("personal-source");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "base.txt"), "baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "work baseline");
    var (personal, work, personalRegistry, workRegistry) = await ConnectedProjects(workspace, bare, personalJunk, personalRepo, workRepo);
    var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    await File.WriteAllTextAsync(Path.Combine(personalRepo, "pending.txt"), "pending change\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "pending change");
    var cursorBefore = (await personalRegistry.Get(personal.Id)).LastPersonalCommit;
    await personalEngine.SyncJunk(personal.Id, "test passphrase", push: false);
    var personalPackage = Directory.GetFiles(Path.Combine(personalJunk, personal.Folder, "channels", personal.ChannelId, "packages", "personal-to-work"), "*.age").Single();
    var originalBytes = await File.ReadAllBytesAsync(personalPackage);
    var localTransportHead = (await Git(personalJunk, "rev-parse", "HEAD")).Trim();

    var conflictingRemotePackage = Path.Combine(work.JunkPath, work.Folder, "channels", work.ChannelId, "packages", "personal-to-work", Path.GetFileName(personalPackage));
    Directory.CreateDirectory(Path.GetDirectoryName(conflictingRemotePackage)!);
    var remoteBytes = (byte[])originalBytes.Clone();
    remoteBytes[^1] ^= 1;
    await File.WriteAllBytesAsync(conflictingRemotePackage, remoteBytes);
    await Git(work.JunkPath, "add", "--", Path.GetRelativePath(work.JunkPath, conflictingRemotePackage));
    await Git(work.JunkPath, "commit", "-m", "conflicting remote package fixture");
    await Git(work.JunkPath, "push");

    await Throws(() => personalEngine.SyncJunk(personal.Id, "test passphrase", push: false), "non-fast-forward junk pull");
    var bytesAfterFailedPull = await File.ReadAllBytesAsync(personalPackage);
    Check(originalBytes.AsSpan().SequenceEqual(bytesAfterFailedPull), "failed pull altered pending ciphertext bytes");
    Equal(localTransportHead, (await Git(personalJunk, "rev-parse", "HEAD")).Trim(), "failed pull moved local transport HEAD");
    Equal(cursorBefore, (await personalRegistry.Get(personal.Id)).LastPersonalCommit, "failed pull advanced outbound cursor");
}

static async Task OutOfOrderDuplicateAndWrongCommit()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = workspace.PathFor("personal-source");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "code.txt"), "base\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "work baseline");
    var (personal, work, personalRegistry, workRegistry) = await ConnectedProjects(workspace, bare, personalJunk, personalRepo, workRepo);
    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await Git(personalRepo, "config", "user.name", "SyncApp Test");
    await Git(personalRepo, "config", "user.email", "syncapp-test@example.invalid");
    await File.AppendAllTextAsync(Path.Combine(personalRepo, "code.txt"), "A\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "A");
    await File.AppendAllTextAsync(Path.Combine(personalRepo, "code.txt"), "B\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "B");
    await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);
    await workEngine.SyncJunk(work.Id, "test passphrase", push: false);
    var changes = OrderChanges(await workEngine.Inbox(work.Id, "test passphrase"));
    var originalDigest = await new GitService().Digest(workRepo, "HEAD");
    await Throws(() => workEngine.Apply(work.Id, changes[1].ChangeId, "test passphrase"), "missing predecessor");
    Equal(originalDigest, await new GitService().Digest(workRepo, "HEAD"), "out-of-order changed work HEAD");
    Equal("", await Git(workRepo, "status", "--porcelain=v1"), "out-of-order changed worktree");
    await workEngine.Apply(work.Id, changes[0].ChangeId, "test passphrase");
    await Throws(() => workEngine.Apply(work.Id, changes[0].ChangeId, "test passphrase"), "duplicate A");
    await workEngine.Apply(work.Id, changes[1].ChangeId, "test passphrase");
    await File.AppendAllTextAsync(Path.Combine(workRepo, "code.txt"), "unexpected manual edit\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "wrong W");
    await Throws(() => workEngine.Confirm(work.Id, "test passphrase"), "wrong manual commit tree");
    Equal(2, (await workRegistry.Get(work.Id)).Session!.ChangeIds.Count, "failed confirmation erased pending group");
}

static async Task MismatchedBaselineIsRejected()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = await workspace.NewRepository("personal-source");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(personalRepo, "code.txt"), "personal baseline\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "prepared personal baseline");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "code.txt"), "different work baseline\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "prepared work baseline");
    await File.WriteAllTextAsync(Path.Combine(personalJunk, "fixture.txt"), "junk fixture\n");
    await Git(personalJunk, "add", "fixture.txt");
    await Git(personalJunk, "commit", "-m", "junk fixture baseline");
    await Git(personalJunk, "push", "-u", "origin", "main");

    var oldDataDir = Environment.GetEnvironmentVariable("SYNCAPP_DATA_DIR");
    try
    {
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("personal-data"));
        var personalRegistry = new Registry();
        var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
        var personal = await personalEngine.CreatePersonal("project-one", personalJunk, personalRepo, "test passphrase");
        await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);
        var workJunk = await workspace.Clone(bare, "work-junk");

        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("work-data"));
        var workRegistry = new Registry();
        var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
        var descriptor = JsonSerializer.Deserialize<ProjectDescriptor>(await File.ReadAllTextAsync(Path.Combine(workJunk, personal.Folder, "project.json")), JsonConfig.Options)!;
        var work = await workEngine.CreateWork(personal.Folder, workJunk, workRepo, "test passphrase", CryptoService.PairFingerprint(descriptor.PersonalSigningKey, descriptor.PersonalRecipient));

        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("personal-data"));
        await personalEngine.AttachWorkKey(personal.Id, work.WorkRecipient!, CryptoService.EncryptionFingerprint(work.WorkRecipient!));
        await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);

        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("work-data"));
        workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
        var originalHead = (await Git(workRepo, "rev-parse", "HEAD")).Trim();
        var originalDigest = await new GitService().Digest(workRepo, "HEAD");
        await ThrowsData(() => workEngine.SyncJunk(work.Id, "test passphrase", push: false), "personal baseline does not match prepared work source");
        Equal(originalHead, (await Git(workRepo, "rev-parse", "HEAD")).Trim(), "mismatched baseline changed work HEAD");
        Equal(originalDigest, await new GitService().Digest(workRepo, "HEAD"), "mismatched baseline changed work source tree");
        Check(!(await workRegistry.Get(work.Id)).BaselineVerified, "mismatched baseline was accepted");
        Equal("", await Git(work.JunkPath, "status", "--porcelain=v1"), "baseline refusal dirtied work junk");
    }
    finally { Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", oldDataDir); }
}

static async Task WorkRegistrationDoesNotDirtyJunk()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var workRepo = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "a.txt"), "base\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "base");
    var personalRepo = workspace.PathFor("personal-source");
    var (_, work, _, _) = await ConnectedProjects(workspace, bare, personalJunk, personalRepo, workRepo);
    var status = await Git(work.JunkPath, "status", "--porcelain=v1");
    Equal("", status, "work-side junk after registration");
}

static async Task TamperedRecipientIsRejected()
{
    using var workspace = new TestWorkspace();
    var (bare, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var personalRepo = await workspace.NewRepository("personal-source");
    await File.WriteAllTextAsync(Path.Combine(personalRepo, "base.txt"), "prepared\n");
    await Git(personalRepo, "add", ".");
    await Git(personalRepo, "commit", "-m", "prepared baseline");
    await File.WriteAllTextAsync(Path.Combine(personalJunk, "fixture.txt"), "fixture\n");
    await Git(personalJunk, "add", ".");
    await Git(personalJunk, "commit", "-m", "junk fixture");
    await Git(personalJunk, "push", "-u", "origin", "main");
    var oldDataDir = Environment.GetEnvironmentVariable("SYNCAPP_DATA_DIR");
    try
    {
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("personal-data"));
        var engine = new SyncEngine(new Registry(), new GitService(), new CryptoService());
        var personal = await engine.CreatePersonal("project-one", personalJunk, personalRepo, "test passphrase");
        var recipient = (await new CryptoService().Generate()).AgeRecipient;
        await ThrowsCrypto(() => engine.AttachWorkKey(personal.Id, recipient, new string('0', 64)), "wrong manually copied work fingerprint");
        var attached = await engine.AttachWorkKey(personal.Id, recipient, CryptoService.EncryptionFingerprint(recipient));
        Equal(recipient, attached.WorkRecipient, "valid manual age recipient was not attached");
        Check(attached.WorkRecipient == recipient, "work age key was not attached");
    }
    finally { Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", oldDataDir); }
}

static async Task LocationAliasIsRejected()
{
    if (OperatingSystem.IsWindows()) return;
    using var workspace = new TestWorkspace();
    var (_, personalJunk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var alias = workspace.PathFor("junk-alias");
    Directory.CreateSymbolicLink(alias, personalJunk);
    var oldDataDir = Environment.GetEnvironmentVariable("SYNCAPP_DATA_DIR");
    try
    {
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("personal-data"));
        var engine = new SyncEngine(new Registry(), new GitService(), new CryptoService());
        await Throws(() => engine.CreatePersonal("project-one", personalJunk, Path.Combine(alias, "source"), "test passphrase"), "source inside junk via symlink alias");
    }
    finally { Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", oldDataDir); }

}

static async Task WorkSubdirectoryIsRejected()
{
    using var workspace = new TestWorkspace();
    var workRepo = await workspace.NewRepository("work-source");
    Directory.CreateDirectory(Path.Combine(workRepo, "subdir"));
    await File.WriteAllTextAsync(Path.Combine(workRepo, "root.txt"), "root\n");
    await File.WriteAllTextAsync(Path.Combine(workRepo, "subdir", "code.txt"), "subdir\n");
    await Git(workRepo, "add", ".");
    await Git(workRepo, "commit", "-m", "base");
    var (bare, cleanJunk) = await workspace.NewBareAndClone("second-transport", "second-personal-junk");
    await Throws(() => ConnectedProjects(workspace, bare, cleanJunk, workspace.PathFor("second-personal-source"), Path.Combine(workRepo, "subdir")), "work repo subdirectory selected");
}

static async Task<(LocalProject Personal, LocalProject Work, Registry PersonalRegistry, Registry WorkRegistry)> ConnectedProjects(
    TestWorkspace workspace, string bare, string personalJunk, string personalRepo, string workRepo,
    bool? workAutocrlf = null)
{
    var oldDataDir = Environment.GetEnvironmentVariable("SYNCAPP_DATA_DIR");
    try
    {
        var git = new GitService();
        var files = await ReadTrackedFiles(git, workRepo, "HEAD");
        Directory.CreateDirectory(personalRepo);
        await Git(personalRepo, "init", "-b", "PERSONAL_BRANCH_SECRET_9bc1");
        await Git(personalRepo, "config", "user.name", "SyncApp Test");
        await Git(personalRepo, "config", "user.email", "syncapp-test@example.invalid");
        await Git(personalRepo, "config", "commit.gpgsign", "false");
        foreach (var entry in files)
        {
            var target = Path.Combine(personalRepo, entry.Path.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await File.WriteAllBytesAsync(target, entry.Bytes);
            if (entry.Mode == "100755") await Git(personalRepo, "add", "--chmod=+x", "--", entry.Path);
            else await Git(personalRepo, "add", "--", entry.Path);
        }
        await Git(personalRepo, "commit", "-m", "prepared personal baseline");
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("personal-data"));
        await File.WriteAllTextAsync(Path.Combine(personalJunk, "fixture.txt"), "junk fixture\n");
        await Git(personalJunk, "add", "fixture.txt");
        await Git(personalJunk, "commit", "-m", "junk fixture baseline");
        await Git(personalJunk, "push", "-u", "origin", "main");
        var personalRegistry = new Registry();
        var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
        var personal = await personalEngine.CreatePersonal("project-one", personalJunk, personalRepo, "test passphrase");
        await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);
        var workJunk = await workspace.Clone(bare, "work-junk");
        if (workAutocrlf.HasValue)
        {
            await Git(workJunk, "config", "core.autocrlf", workAutocrlf.Value ? "true" : "false");
            await Git(workJunk, "checkout-index", "--force", "--", "project-one/project.json");
        }
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("work-data"));
        var workRegistry = new Registry();
        var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
        var descriptor = JsonSerializer.Deserialize<ProjectDescriptor>(
            await File.ReadAllTextAsync(Path.Combine(workJunk, "project-one", "project.json")), JsonConfig.Options)!;
        var work = await workEngine.CreateWork("project-one", workJunk, workRepo, "test passphrase", CryptoService.PairFingerprint(descriptor.PersonalSigningKey, descriptor.PersonalRecipient));
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("personal-data"));
        personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
        await personalEngine.AttachWorkKey(personal.Id, work.WorkRecipient!, CryptoService.EncryptionFingerprint(work.WorkRecipient!));
        await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);
        Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", workspace.PathFor("work-data"));
        workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
        var baselineSync = await workEngine.SyncJunk(work.Id, "test passphrase", push: false);
        Check(!baselineSync.Pushed && baselineSync.CommittedFiles == 0, "work wrote while verifying personal baseline");
        Check((await workRegistry.Get(work.Id)).BaselineVerified, "work baseline digest was not verified");
        work = await workRegistry.Get(work.Id);
        return (personal, work, personalRegistry, workRegistry);
    }
    finally { Environment.SetEnvironmentVariable("SYNCAPP_DATA_DIR", oldDataDir); }
}

static async Task<(LocalProject Personal, LocalProject Work, Registry PersonalRegistry, Registry WorkRegistry)>
    RecoveryFixture(TestWorkspace workspace)
{
    var (bare, junk) = await workspace.NewBareAndClone("transport", "personal-junk");
    var work = await workspace.NewRepository("work-source");
    await File.WriteAllTextAsync(Path.Combine(work, "code.txt"), "base\n");
    await Git(work, "add", ".");
    await Git(work, "commit", "-m", "baseline");
    return await ConnectedProjects(workspace, bare, junk, workspace.PathFor("personal-source"), work);
}

static Func<OperationStage, Task> FailAt(OperationStage stage) => actual => actual == stage
    ? Task.FromException(new IOException("fault: " + stage)) : Task.CompletedTask;

static async Task ThrowsFault(Func<Task> operation)
{
    try { await operation(); }
    catch (IOException error) when (error.Message.StartsWith("fault:", StringComparison.Ordinal)) { return; }
    throw new Exception("Expected injected interruption");
}

static async Task<IReadOnlyList<ChangePayload>> PrepareRecoveryChanges(LocalProject personal, LocalProject work, Registry personalRegistry, Registry workRegistry)
{
    var workEngine = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    var personalEngine = new SyncEngine(personalRegistry, new GitService(), new CryptoService());
    await Git(personal.RepoPath, "config", "user.name", "SyncApp Test");
    await Git(personal.RepoPath, "config", "user.email", "syncapp-test@example.invalid");
    foreach (var name in new[] { "A", "B" })
    {
        await File.AppendAllTextAsync(Path.Combine(personal.RepoPath, "code.txt"), name + "\n");
        await Git(personal.RepoPath, "add", ".");
        await Git(personal.RepoPath, "commit", "-m", name);
    }
    await personalEngine.SyncJunk(personal.Id, "test passphrase", push: true);
    await workEngine.SyncJunk(work.Id, "test passphrase", push: false);
    return OrderChanges(await workEngine.Inbox(work.Id, "test passphrase"));
}

static async Task ApplyCheckpointRecovery()
{
    foreach (var point in new[] { OperationStage.ApplyJournalSaved, OperationStage.ApplyFilesWritten })
    {
        using var workspace = new TestWorkspace();
        var (personal, work, personalRegistry, workRegistry) = await RecoveryFixture(workspace);
        var changes = await PrepareRecoveryChanges(personal, work, personalRegistry, workRegistry);
        var failing = new SyncEngine(workRegistry, new GitService(), new CryptoService(), FailAt(point));
        await ThrowsFault(() => failing.Apply(work.Id, changes[0].ChangeId, "test passphrase"));
        var restarted = new SyncEngine(workRegistry, new GitService(), new CryptoService());
        var restored = await restarted.Recover(work.Id, "test passphrase");
        if (point == OperationStage.ApplyJournalSaved)
        {
            Check(restored.Session == null, "unapplied session not cleared");
            Equal("base\n", await File.ReadAllTextAsync(Path.Combine(work.RepoPath, "code.txt")), "files changed before apply");
            await restarted.Apply(work.Id, changes[0].ChangeId, "test passphrase");
        }
        else Equal(1, restored.Session!.ChangeIds.Count, "applied A not recovered exactly once");
        await restarted.Apply(work.Id, changes[1].ChangeId, "test passphrase");
        await Git(work.RepoPath, "commit", "-m", "manual group");
        Equal(2, (await restarted.Confirm(work.Id, "test passphrase")).ChangeIds.Count, "recovered accumulated group");
    }
}

static async Task PendingManualCommitRecovery()
{
    using var workspace = new TestWorkspace();
    var (personal, work, personalRegistry, workRegistry) = await RecoveryFixture(workspace);
    var changes = await PrepareRecoveryChanges(personal, work, personalRegistry, workRegistry);
    await new SyncEngine(workRegistry, new GitService(), new CryptoService()).Apply(work.Id, changes[0].ChangeId, "test passphrase");
    var failing = new SyncEngine(workRegistry, new GitService(), new CryptoService(), FailAt(OperationStage.ApplyFilesWritten));
    await ThrowsFault(() => failing.Apply(work.Id, changes[1].ChangeId, "test passphrase"));
    await Git(work.RepoPath, "commit", "-m", "manual commit while app interrupted");
    var head = (await Git(work.RepoPath, "rev-parse", "HEAD")).Trim();
    var restarted = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    var recovered = await restarted.Recover(work.Id, "test passphrase");
    Check(recovered.Session == null, "manual committed group not finalized");
    Equal(2, recovered.Maps.Single().ChangeIds.Count, "group mapping incorrect");
    await restarted.Confirm(work.Id, "test passphrase");
    Equal(1, (await workRegistry.Get(work.Id)).Maps.Count, "idempotent confirmation duplicated map");
    Equal(head, (await Git(work.RepoPath, "rev-parse", "HEAD")).Trim(), "recovery created target commit");
}

static async Task PendingRecoveryPreservesChanges()
{
    using var workspace = new TestWorkspace();
    var (personal, work, personalRegistry, workRegistry) = await RecoveryFixture(workspace);
    var changes = await PrepareRecoveryChanges(personal, work, personalRegistry, workRegistry);
    var failing = new SyncEngine(workRegistry, new GitService(), new CryptoService(), FailAt(OperationStage.ApplyFilesWritten));
    await ThrowsFault(() => failing.Apply(work.Id, changes[0].ChangeId, "test passphrase"));
    await File.AppendAllTextAsync(Path.Combine(work.RepoPath, "code.txt"), "user extra\n");
    await Git(work.RepoPath, "add", ".");
    await Git(work.RepoPath, "commit", "-m", "wrong manual result");
    var head = (await Git(work.RepoPath, "rev-parse", "HEAD")).Trim();
    await Throws(() => new SyncEngine(workRegistry, new GitService(), new CryptoService()).Recover(work.Id, "test passphrase"), "wrong committed pending result");
    Equal(head, (await Git(work.RepoPath, "rev-parse", "HEAD")).Trim(), "wrong recovery rewrote history");
    Check((await File.ReadAllTextAsync(Path.Combine(work.RepoPath, "code.txt"))).Contains("user extra"), "user edit lost");
    Check((await workRegistry.Get(work.Id)).Session!.PendingChangeId != null, "refused recovery lost journal");
}

static async Task ConfirmationCheckpointRecovery()
{
    using var workspace = new TestWorkspace();
    var (personal, work, personalRegistry, workRegistry) = await RecoveryFixture(workspace);
    var changes = await PrepareRecoveryChanges(personal, work, personalRegistry, workRegistry);
    var failing = new SyncEngine(workRegistry, new GitService(), new CryptoService(), FailAt(OperationStage.ConfirmationCommitted));
    await failing.Apply(work.Id, changes[0].ChangeId, "test passphrase");
    await Git(work.RepoPath, "commit", "-m", "manual");
    await ThrowsFault(() => failing.Confirm(work.Id, "test passphrase"));
    var restarted = new SyncEngine(workRegistry, new GitService(), new CryptoService());
    await restarted.Recover(work.Id, "test passphrase");
    await restarted.Confirm(work.Id, "test passphrase");
    Equal(1, (await workRegistry.Get(work.Id)).Maps.Count, "confirmation map duplicated");
    var receipts = Path.Combine(work.JunkPath, work.Folder, "channels", work.ChannelId, "receipts");
    Check(!Directory.Exists(receipts) || Directory.GetFiles(receipts, "*.age", SearchOption.AllDirectories).Length == 0, "Work created a transport receipt");
    Equal((await Git(work.JunkPath, "rev-parse", "origin/main")).Trim(), (await Git(work.JunkPath, "rev-parse", "HEAD")).Trim(), "Confirm changed Work junk beyond pulled origin");
}

static async Task PrivateScratchIsolation()
{
    using var workspace = new TestWorkspace();
    var fakeTemp = workspace.PathFor("junk-temp");
    Directory.CreateDirectory(fakeTemp);
    var old = Environment.GetEnvironmentVariable("TMPDIR");
    Environment.SetEnvironmentVariable("TMPDIR", fakeTemp);
    var root = workspace.PathFor("state");
    try
    {
        string operationPath;
        using (var scratch = PrivateWorkspace.Create(root))
        {
            operationPath = scratch.DirectoryPath;
            var secret = await scratch.WritePrivateFile("test.txt", Encoding.UTF8.GetBytes("test content"));
            Check(secret.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal), "scratch followed OS temp");
            if (!OperatingSystem.IsWindows())
            {
                Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(secret), "secret file permissions");
                Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(operationPath), "scratch directory permissions");
            }
        }
        Check(!Directory.Exists(operationPath), "scratch leaked after dispose");
        await new CryptoService().Generate(root);
        Equal(0, Directory.GetFileSystemEntries(fakeTemp).Length, "crypto used OS temp inside junk");
        Equal(0, Directory.GetFileSystemEntries(Path.Combine(root, "scratch")).Length, "crypto scratch leaked");
        if (!OperatingSystem.IsWindows())
        {
            var alias = workspace.PathFor("state-alias");
            Directory.CreateSymbolicLink(alias, root);
            await Throws(() => Task.Run(() => { using var scratch = PrivateWorkspace.Create(alias); }), "scratch symlink alias");
        }
    }
    finally { Environment.SetEnvironmentVariable("TMPDIR", old); }
}

static async Task DirtyRepositoryIsBlocked()
{
    using var workspace = new TestWorkspace();
    var repo = await workspace.NewRepository("repo");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "base\n");
    await Git(repo, "add", "a.txt");
    await Git(repo, "commit", "-m", "base");
    var service = new GitService();
    await service.EnsureClean(repo);
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "changed\n");
    await Throws(() => service.EnsureClean(repo), "tracked worktree change");
    await Git(repo, "add", "a.txt");
    await Throws(() => service.EnsureClean(repo), "staged change");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "changed again\n");
    await Throws(() => service.EnsureWorktreeMatchesIndex(repo), "modified file after staging");
    await Git(repo, "checkout", "--", "a.txt");
    await File.WriteAllTextAsync(Path.Combine(repo, "untracked.txt"), "extra\n");
    await Throws(() => service.EnsureWorktreeMatchesIndex(repo), "untracked file");
}

static async Task BranchAndMergeAreBlocked()
{
    using var workspace = new TestWorkspace();
    var repo = await workspace.NewRepository("repo");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "base\n");
    await Git(repo, "add", "a.txt");
    await Git(repo, "commit", "-m", "base");
    var service = new GitService();
    await service.EnsureBranch(repo, "main");
    await Throws(() => service.EnsureBranch(repo, "other"), "wrong branch");
    var gitDir = (await Git(repo, "rev-parse", "--absolute-git-dir")).Trim();
    await File.WriteAllTextAsync(Path.Combine(gitDir, "MERGE_HEAD"), new string('0', 40) + "\n");
    await Throws(() => service.EnsureBranch(repo, "main"), "merge marker");
}

static async Task HiddenIndexFlagsAreBlocked()
{
    using var workspace = new TestWorkspace();
    var repo = await workspace.NewRepository("repo");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "base\n");
    await Git(repo, "add", "a.txt");
    await Git(repo, "commit", "-m", "base");
    var service = new GitService();

    await Git(repo, "update-index", "--skip-worktree", "a.txt");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "modified despite skip-worktree\n");
    await Throws(() => service.EnsureClean(repo), "skip-worktree edit");
    await Git(repo, "update-index", "--no-skip-worktree", "a.txt");
    await Git(repo, "checkout", "--", "a.txt");

    await Git(repo, "update-index", "--assume-unchanged", "a.txt");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "modified despite assume-unchanged\n");
    await Throws(() => service.EnsureClean(repo), "assume-unchanged edit");
}

static async Task RebaseAndSequencerAreBlocked()
{
    using var workspace = new TestWorkspace();
    var repo = await workspace.NewRepository("repo");
    await File.WriteAllTextAsync(Path.Combine(repo, "a.txt"), "base\n");
    await Git(repo, "add", "a.txt");
    await Git(repo, "commit", "-m", "base");
    var gitDir = (await Git(repo, "rev-parse", "--absolute-git-dir")).Trim();
    var service = new GitService();
    foreach (var marker in new[] { "rebase-merge", "rebase-apply", "sequencer" })
    {
        var markerPath = Path.Combine(gitDir, marker);
        Directory.CreateDirectory(markerPath);
        await Throws(() => service.EnsureBranch(repo, "main"), marker);
        Directory.Delete(markerPath);
    }
}

static async Task CaseCollisionIsBlocked()
{
    if (OperatingSystem.IsWindows()) return;
    using var workspace = new TestWorkspace();
    var repo = await workspace.NewRepository("repo");
    await File.WriteAllTextAsync(Path.Combine(repo, "Foo.txt"), "one\n");
    await File.WriteAllTextAsync(Path.Combine(repo, "foo.txt"), "two\n");
    await Git(repo, "add", ".");
    await Git(repo, "commit", "-m", "case collision");
    try { await new GitService().Entries(repo, "HEAD"); }
    catch (NotSupportedException) { return; }
    throw new Exception("Windows-incompatible case collision accepted from WSL");
}

static Task UnsafePathsAreRejected()
{
    foreach (var path in new[] { "../secret", "/absolute", "a/../b", ".git/config", "nested/.GIT/config", ".git /config", "C:/drive", "CON.txt", "a\\b", "a//b", "trailing.", "trailing ", "folder./file", "folder /file" })
    {
        try { GitService.ValidatePath(path); }
        catch (InvalidDataException) { continue; }
        throw new Exception($"Unsafe path accepted: {path}");
    }
    foreach (var path in new[] { "a/b.cs", "проект/имя файла.txt" }) GitService.ValidatePath(path);
    return Task.CompletedTask;
}

static async Task CryptoRoundtripAndSigner()
{
    using var workspace = new TestWorkspace();
    var stateRoot = workspace.PathFor("state");
    var service = new CryptoService();
    var previousAgePath = Environment.GetEnvironmentVariable("AGE_PATH");
    Environment.SetEnvironmentVariable("AGE_PATH", Path.Combine(stateRoot, "missing-age-tool"));
    try
    {
        var sender = await service.Generate(stateRoot);
        var receiver = await service.Generate(stateRoot);
        var other = await service.Generate(stateRoot);
        Check(sender.AgeIdentity.Contains("# created: ", StringComparison.Ordinal), "built-in identity is missing the CLI creation comment");
        Check(sender.AgeIdentity.Contains($"# public key: {sender.AgeRecipient}", StringComparison.Ordinal), "built-in identity is missing the recipient comment");
        var payload = RandomNumberGenerator.GetBytes(1024 * 1024);
        var encrypted = await service.Protect(payload, receiver.AgeRecipient, sender).WaitAsync(TimeSpan.FromSeconds(30));
        Check(encrypted.AsSpan().IndexOf(payload.AsSpan(0, 128)) < 0, "ciphertext contains plaintext prefix");
        var opened = await service.Open(encrypted, receiver, sender.SigningPublicPem, workspaceRoot: stateRoot).WaitAsync(TimeSpan.FromSeconds(30));
        Check(payload.AsSpan().SequenceEqual(opened), "large package changed during encryption");
        await ThrowsCrypto(() => service.Open(encrypted, receiver, other.SigningPublicPem, workspaceRoot: stateRoot), "untrusted signer");

        var tamperedCiphertext = encrypted.ToArray();
        tamperedCiphertext[^10] ^= 1;
        await ThrowsCrypto(() => service.Open(tamperedCiphertext, receiver, sender.SigningPublicPem, workspaceRoot: stateRoot), "tampered ciphertext");
    }
    finally
    {
        Environment.SetEnvironmentVariable("AGE_PATH", previousAgePath);
    }
}

static async Task LegacyAgeCliIdentityAndCiphertext()
{
    using var workspace = new TestWorkspace();
    var fixtureDirectory = Path.Combine(AppContext.BaseDirectory, "fixtures", "age-v1");
    var identityText = await File.ReadAllTextAsync(Path.Combine(fixtureDirectory, "identity.txt"));
    var recipientLine = identityText.Split('\n').Single(line => line.StartsWith("# public key: ", StringComparison.Ordinal));
    var recipient = recipientLine["# public key: ".Length..].Trim();
    var signingPublicKey = (await File.ReadAllTextAsync(Path.Combine(fixtureDirectory, "signing-public.pem")))
        .Replace("\r\n", "\n", StringComparison.Ordinal);
    var ciphertext = await File.ReadAllBytesAsync(Path.Combine(fixtureDirectory, "envelope.age"));
    var expectedPayload = await File.ReadAllBytesAsync(Path.Combine(fixtureDirectory, "payload.bin"));
    var legacyKeys = new SecretKeys
    {
        AgeIdentity = identityText,
        AgeRecipient = recipient,
        SigningPublicPem = signingPublicKey
    };

    var keyPath = Path.Combine(workspace.PathFor("state"), "legacy.key");
    CryptoService.SaveKeys(keyPath, legacyKeys, "legacy test passphrase");
    var loadedKeys = CryptoService.LoadKeys(keyPath, "legacy test passphrase");
    Equal(identityText, loadedKeys.AgeIdentity, "commented age identity changed when loading legacy key file");
    Equal(recipient, loadedKeys.AgeRecipient, "legacy age recipient changed when loading key file");

    var service = new CryptoService();
    var opened = await service.Open(ciphertext, loadedKeys, signingPublicKey);
    Check(expectedPayload.AsSpan().SequenceEqual(opened), "reference age-v1 CLI ciphertext payload changed");

    var crlfKeys = new SecretKeys
    {
        AgeIdentity = identityText.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\r\n", StringComparison.Ordinal),
        AgeRecipient = recipient,
        SigningPublicPem = signingPublicKey
    };
    var openedFromCrLfIdentity = await service.Open(ciphertext, crlfKeys, signingPublicKey);
    Check(expectedPayload.AsSpan().SequenceEqual(openedFromCrLfIdentity), "commented CRLF age identity could not decrypt reference ciphertext");

    var tamperedCiphertext = ciphertext.ToArray();
    tamperedCiphertext[tamperedCiphertext.Length / 2] ^= 1;
    await ThrowsCrypto(() => service.Open(tamperedCiphertext, loadedKeys, signingPublicKey), "tampered reference age-v1 ciphertext");
    await ThrowsCrypto(() => service.Open(ciphertext[..^16], loadedKeys, signingPublicKey), "truncated reference age-v1 ciphertext");

    var wrongRecipient = await service.GenerateAgeOnly(workspace.PathFor("other-state"));
    await ThrowsCrypto(() => service.Open(ciphertext, wrongRecipient, signingPublicKey), "wrong legacy age recipient");
}

static async Task ThrowsCrypto(Func<Task> operation, string context)
{
    try { await operation(); }
    catch (Exception error) when (error is CryptographicException or InvalidOperationException or InvalidDataException) { return; }
    throw new Exception($"Expected cryptographic rejection: {context}");
}

static async Task ThrowsData(Func<Task> operation, string context)
{
    try { await operation(); }
    catch (InvalidDataException) { return; }
    throw new Exception($"Expected invalid data rejection: {context}");
}

static async Task<string> Git(string directory, params string[] args)
{
    var start = new ProcessStartInfo("git") { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
    foreach (var arg in args) start.ArgumentList.Add(arg);
    using var process = Process.Start(start) ?? throw new Exception("git failed to start");
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    if (process.ExitCode != 0) throw new Exception($"git {string.Join(' ', args)} failed: {await stderr}");
    return await stdout;
}

static List<ChangePayload> OrderChanges(IEnumerable<ChangePayload> changes)
{
    var remaining = changes.ToList();
    var ordered = new List<ChangePayload>(remaining.Count);
    string? previous = null;
    while (remaining.Count > 0)
    {
        var next = remaining.SingleOrDefault(change => change.PreviousChangeId == previous)
            ?? throw new Exception("Incoming package chain has no unique next item");
        ordered.Add(next);
        remaining.Remove(next);
        previous = next.ChangeId;
    }
    return ordered;
}

static async Task<List<(string Mode, string Path, byte[] Bytes)>> ReadTrackedFiles(GitService git, string repo, string revision)
{
    var entries = await git.Entries(repo, revision);
    var files = new List<(string Mode, string Path, byte[] Bytes)>(entries.Count);
    foreach (var entry in entries)
        files.Add((entry.Mode, entry.Path, await git.Run(repo, "cat-file", "blob", entry.Id)));
    return files;
}

static async Task Throws(Func<Task> operation, string context)
{
    try { await operation(); }
    catch (InvalidOperationException) { return; }
    throw new Exception($"Expected rejection: {context}");
}

static void Equal<T>(T expected, T actual, string context)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"{context}: expected {expected}, got {actual}");
}

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static async Task AssertTransportBlobsDoNotContain(string bare, params string[] plaintextMarkers)
{
    var objects = await Git(bare, "cat-file", "--batch-all-objects", "--batch");
    foreach (var marker in plaintextMarkers)
        Check(!objects.Contains(marker, StringComparison.Ordinal), $"plaintext marker leaked into Git transport: {marker}");
}

sealed class TestWorkspace : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "syncapp-tests-" + Guid.NewGuid().ToString("N"));
    public TestWorkspace() => Directory.CreateDirectory(_root);
    public string PathFor(string name) => Path.Combine(_root, name);

    public async Task<(string Bare, string Clone)> NewBareAndClone(string bareName, string cloneName)
    {
        var bare = PathFor(bareName + ".git");
        Directory.CreateDirectory(bare);
        await Git(bare, "init", "--bare", "-b", "main");
        return (bare, await Clone(bare, cloneName));
    }

    public async Task<string> Clone(string remote, string name)
    {
        var path = PathFor(name);
        await Git(_root, "clone", remote, path);
        await Git(path, "config", "user.name", "SyncApp Test");
        await Git(path, "config", "user.email", "syncapp-test@example.invalid");
        await Git(path, "config", "commit.gpgsign", "false");
        return path;
    }

    public async Task<string> NewRepository(string name)
    {
        var path = Path.Combine(_root, name);
        Directory.CreateDirectory(path);
        await Git(path, "init", "-b", "main");
        await Git(path, "config", "user.name", "SyncApp Test");
        await Git(path, "config", "user.email", "syncapp-test@example.invalid");
        await Git(path, "config", "commit.gpgsign", "false");
        return path;
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static async Task Git(string directory, params string[] args)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new Exception("git failed to start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new Exception($"git {string.Join(' ', args)} failed: {await stderr}");
        await stdout;
    }
}
