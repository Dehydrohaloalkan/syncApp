using System.Text.Json;

namespace SyncApp;

public sealed class Registry
{
    public string Root { get; }
    private readonly string _file;
    private readonly SemaphoreSlim _gate = new(1, 1);
    public static string DefaultRoot() => Environment.GetEnvironmentVariable("SYNCAPP_DATA_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SyncApp");
    public Registry()
    {
        Root = Path.GetFullPath(DefaultRoot());
        PrivateWorkspace.EnsureNoLinks(Root);
        Directory.CreateDirectory(Root);
        _file = Path.Combine(Root, "projects.json");
    }

    public async Task<List<LocalProject>> All()
    {
        await _gate.WaitAsync();
        try { return Read(); }
        finally { _gate.Release(); }
    }

    public async Task<LocalProject> Get(string id)
    {
        var project = (await All()).FirstOrDefault(x => x.Id == id);
        return project ?? throw new KeyNotFoundException("Проект не найден");
    }

    public async Task Save(LocalProject project)
    {
        await _gate.WaitAsync();
        try
        {
            var list = Read(); var index = list.FindIndex(x => x.Id == project.Id);
            if (index < 0) list.Add(project); else list[index] = project;
            var temp = Path.Combine(Root, ".projects-" + Guid.NewGuid().ToString("N"));
            try
            {
                await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    await JsonSerializer.SerializeAsync(stream, list, JsonConfig.Options);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temp, _file, true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        finally { _gate.Release(); }
    }

    private List<LocalProject> Read() => File.Exists(_file)
        ? JsonSerializer.Deserialize<List<LocalProject>>(File.ReadAllText(_file), JsonConfig.Options) ?? [] : [];
}
