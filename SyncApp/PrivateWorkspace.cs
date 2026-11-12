using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SyncApp;

/// <summary>Scratch data owned by one operation, independent of OS temporary-directory settings.</summary>
public sealed class PrivateWorkspace : IDisposable
{
    public string DirectoryPath { get; }

    private PrivateWorkspace(string directory) => DirectoryPath = directory;

    public static PrivateWorkspace Create(string? stateRoot = null)
    {
        var root = Path.GetFullPath(stateRoot ?? Registry.DefaultRoot());
        EnsureNoLinks(root);
        var scratch = Path.Combine(root, "scratch");
        EnsureNoLinks(scratch);
        CreatePrivateDirectory(scratch);
        var directory = Path.Combine(scratch, Guid.NewGuid().ToString("N"));
        CreatePrivateDirectory(directory);
        return new PrivateWorkspace(directory);
    }

    private static void CreatePrivateDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
            RestrictWindowsDirectory(path);
        }
        else
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        EnsureNoLinks(path);
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictWindowsDirectory(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new InvalidOperationException("Не определён текущий Windows-пользователь");
        var permissions = new DirectorySecurity();
        permissions.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        permissions.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(permissions);
    }

    public string FilePath(string name)
    {
        if (name != Path.GetFileName(name) || name is "" or "." or ".." || name.Contains('\\'))
            throw new ArgumentException("Некорректное имя временного файла");
        EnsureNoLinks(DirectoryPath);
        return Path.Combine(DirectoryPath, name);
    }

    public async Task<string> WritePrivateFile(string name, byte[] content)
    {
        var path = FilePath(name);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var file = new FileStream(path, options);
        await file.WriteAsync(content);
        return path;
    }

    public static void EnsureNoLinks(string path)
    {
        for (var current = Path.GetFullPath(path); current != null; current = Path.GetDirectoryName(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Символическая ссылка или junction в пути: " + current);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    public void Dispose()
    {
        if (!Directory.Exists(DirectoryPath)) return;
        EnsureNoLinks(DirectoryPath);
        Directory.Delete(DirectoryPath, recursive: true);
    }
}
