using System.Text.Json.Serialization;

namespace SyncApp;

public static class JsonConfig
{
    public static readonly System.Text.Json.JsonSerializerOptions Options = new(System.Text.Json.JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() }
    };
}

public enum Side { Personal, Work }
public enum Direction { PersonalToWork }

public sealed class ProjectDescriptor
{
    public int Version { get; set; } = 3;
    public string ProjectId { get; set; } = Guid.NewGuid().ToString("N");
    public string ChannelId { get; set; } = Guid.NewGuid().ToString("N");
    public int Epoch { get; set; } = 1;
    public string PersonalRecipient { get; set; } = "";
    public string PersonalSigningKey { get; set; } = "";
    public string? WorkRecipient { get; set; }
}

public sealed class LocalProject
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public Side Side { get; set; }
    public string Folder { get; set; } = "";
    public string JunkPath { get; set; } = "";
    public string RepoPath { get; set; } = "";
    public string Branch { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string ChannelId { get; set; } = "";
    public int Epoch { get; set; } = 1;
    public string KeysFile { get; set; } = "";
    public string PersonalRecipient { get; set; } = "";
    public string PersonalSigningKey { get; set; } = "";
    public string? WorkRecipient { get; set; }
    public string? BaselineCommit { get; set; }
    public bool BaselineVerified { get; set; }
    public string? LastPersonalCommit { get; set; }
    public string? LastWorkCommit { get; set; }
    public string? LastPersonalChangeId { get; set; }
    public string? CurrentDigest { get; set; }
    public Dictionary<string, string> OwnedTransportFiles { get; set; } = [];
    public List<string> OwnedTransportCommits { get; set; } = [];
    public TransportCommitIntent? PendingTransportCommit { get; set; }
    public List<PreparedPersonalChange> PendingPersonalChanges { get; set; } = [];
    public List<string> Published { get; set; } = [];
    public List<string> Applied { get; set; } = [];
    public List<CommitMap> Maps { get; set; } = [];
    public ApplySession? Session { get; set; }
}

public sealed class TransportCommitIntent
{
    public string ParentCommit { get; set; } = "";
    public string Tree { get; set; } = "";
}

public sealed class PreparedPersonalChange
{
    public string SourceCommit { get; set; } = "";
    public string ChangeId { get; set; } = "";
}

// Constructor-injected checkpoints let tests interrupt real operations without HTTP test switches.
public enum OperationStage
{
    ApplyJournalSaved, ApplyFilesWritten, ConfirmationCommitted
}

public sealed class CommitMap
{
    public List<string> ChangeIds { get; set; } = [];
    public string TargetCommit { get; set; } = "";
    public string ResultDigest { get; set; } = "";
}

public sealed class ApplySession
{
    public string OriginalHead { get; set; } = "";
    public string ExpectedDigest { get; set; } = "";
    public string ExpectedTree { get; set; } = "";
    public string Direction { get; set; } = "";
    public List<string> ChangeIds { get; set; } = [];
    public string? PendingChangeId { get; set; }
    public string? PendingResultDigest { get; set; }
}

public sealed class ChangePayload
{
    public int Version { get; set; } = 3;
    public string ProjectId { get; set; } = "";
    public string ChannelId { get; set; } = "";
    public int Epoch { get; set; } = 1;
    public string ChangeId { get; set; } = "";
    public Direction Direction { get; set; }
    public string? PreviousChangeId { get; set; }
    public string SourceCommit { get; set; } = "";
    public string ParentCommit { get; set; } = "";
    public string Message { get; set; } = "";
    public string BaseDigest { get; set; } = "";
    public string ResultDigest { get; set; } = "";
    public string PatchBase64 { get; set; } = "";
}

public sealed class BaselinePayload
{
    public int Version { get; set; } = 3;
    public string ProjectId { get; set; } = "";
    public string ChannelId { get; set; } = "";
    public int Epoch { get; set; } = 1;
    public string Digest { get; set; } = "";
}

public sealed class SignedEnvelope
{
    public int Version { get; set; } = 1;
    public string PayloadBase64 { get; set; } = "";
    public string SignatureBase64 { get; set; } = "";
    public string SigningKey { get; set; } = "";
}

public sealed class JunkSyncResult
{
    public int PulledPackages { get; set; }
    public int PreparedChanges { get; set; }
    public int CommittedFiles { get; set; }
    public bool Pushed { get; set; }
}
