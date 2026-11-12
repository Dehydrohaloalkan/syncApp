using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SyncApp;

public sealed class SecretKeys
{
    public string AgeIdentity { get; set; } = "";
    public string AgeRecipient { get; set; } = "";
    public string SigningPrivatePem { get; set; } = "";
    public string SigningPublicPem { get; set; } = "";
}

public sealed class CryptoService
{
    private static string AgeBinary => Environment.GetEnvironmentVariable("AGE_PATH") is { Length: > 0 } path ? path : "age";
    private static string KeygenBinary => Environment.GetEnvironmentVariable("AGE_PATH") is { Length: > 0 } path ? Path.Combine(Path.GetDirectoryName(path)!, OperatingSystem.IsWindows() ? "age-keygen.exe" : "age-keygen") : "age-keygen";

    private static async Task<byte[]> Execute(string binary, byte[]? input, params string[] args)
    {
        var start = new ProcessStartInfo(binary) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Не удалось запустить {binary}");
        using var output = new MemoryStream();
        var stdout = process.StandardOutput.BaseStream.CopyToAsync(output);
        var stderr = process.StandardError.ReadToEndAsync();
        if (input != null) { await process.StandardInput.BaseStream.WriteAsync(input); await process.StandardInput.BaseStream.FlushAsync(); }
        process.StandardInput.Close();
        await Task.WhenAll(stdout, stderr);
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new InvalidOperationException($"{Path.GetFileName(binary)}: {await stderr}");
        return output.ToArray();
    }

    public async Task<SecretKeys> Generate(string? workspaceRoot = null)
    {
        var (identity, recipient) = await GenerateAgeIdentity(workspaceRoot);
        using var rsa = RSA.Create(3072);
        return new SecretKeys { AgeIdentity = identity, AgeRecipient = recipient, SigningPrivatePem = rsa.ExportRSAPrivateKeyPem(), SigningPublicPem = rsa.ExportSubjectPublicKeyInfoPem() };
    }

    public async Task<SecretKeys> GenerateAgeOnly(string? workspaceRoot = null)
    {
        var (identity, recipient) = await GenerateAgeIdentity(workspaceRoot);
        return new SecretKeys { AgeIdentity = identity, AgeRecipient = recipient };
    }

    private static async Task<(string Identity, string Recipient)> GenerateAgeIdentity(string? workspaceRoot)
    {
        using var workspace = PrivateWorkspace.Create(workspaceRoot);
        var temp = workspace.FilePath("identity.txt");
        await Execute(KeygenBinary, null, "-o", temp);
        var identity = await File.ReadAllTextAsync(temp);
        var recipient = identity.Split('\n').FirstOrDefault(x => x.StartsWith("# public key: "))?[14..].Trim()
            ?? throw new InvalidDataException("age-keygen не вернул публичный ключ");
        return (identity, recipient);
    }

    public static string Fingerprint(string publicPem) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(publicPem))).ToLowerInvariant();
    public static string PairFingerprint(string publicPem, string recipient) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(publicPem + "\0" + recipient))).ToLowerInvariant();
    public static string EncryptionFingerprint(string recipient) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(recipient))).ToLowerInvariant();

    public static void SaveKeys(string path, SecretKeys keys, string passphrase)
    {
        if (passphrase.Length < 8) throw new ArgumentException("Пароль ключей должен содержать не меньше 8 символов");
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, 250_000, HashAlgorithmName.SHA256, 32);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(keys, JsonConfig.Options);
        var ciphertext = new byte[plaintext.Length]; var tag = new byte[16];
        using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, ciphertext, tag);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        var data = new byte[16 + 12 + 16 + ciphertext.Length];
        salt.CopyTo(data, 0); nonce.CopyTo(data, 16); tag.CopyTo(data, 28); ciphertext.CopyTo(data, 44);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, data);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public static SecretKeys LoadKeys(string path, string passphrase)
    {
        var data = File.ReadAllBytes(path);
        if (data.Length < 44) throw new InvalidDataException("Повреждён файл ключей");
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, data[..16], 250_000, HashAlgorithmName.SHA256, 32);
        var plaintext = new byte[data.Length - 44];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(data.AsSpan(16, 12), data.AsSpan(44), data.AsSpan(28, 16), plaintext);
            return JsonSerializer.Deserialize<SecretKeys>(plaintext, JsonConfig.Options) ?? throw new InvalidDataException("Файл ключей пуст");
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plaintext); }
    }

    public async Task<byte[]> Protect(byte[] payload, string recipient, SecretKeys signer)
    {
        using var rsa = RSA.Create(); rsa.ImportFromPem(signer.SigningPrivatePem);
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new SignedEnvelope { PayloadBase64 = Convert.ToBase64String(payload), SignatureBase64 = Convert.ToBase64String(signature), SigningKey = signer.SigningPublicPem }, JsonConfig.Options);
        return await Execute(AgeBinary, envelope, "-r", recipient);
    }

    public async Task<byte[]> Open(byte[] ciphertext, SecretKeys recipient, string? pinnedSigner, string? expectedFingerprint = null, string? workspaceRoot = null)
    {
        using var workspace = PrivateWorkspace.Create(workspaceRoot);
        var temp = await workspace.WritePrivateFile("identity.txt", Encoding.UTF8.GetBytes(recipient.AgeIdentity));
        var plain = await Execute(AgeBinary, ciphertext, "-d", "-i", temp);
        var env = JsonSerializer.Deserialize<SignedEnvelope>(plain, JsonConfig.Options) ?? throw new InvalidDataException("Некорректный контейнер");
        if (env.Version != 1) throw new NotSupportedException("Версия контейнера не поддерживается");
        if (pinnedSigner != null && !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(env.SigningKey), Encoding.UTF8.GetBytes(pinnedSigner))) throw new CryptographicException("Подпись другого устройства");
        if (pinnedSigner == null && (expectedFingerprint == null || !string.Equals(expectedFingerprint, Fingerprint(env.SigningKey), StringComparison.OrdinalIgnoreCase))) throw new CryptographicException("Отпечаток отправителя не подтверждён");
        var payload = Convert.FromBase64String(env.PayloadBase64);
        using var rsa = RSA.Create(); rsa.ImportFromPem(env.SigningKey);
        if (!rsa.VerifyData(payload, Convert.FromBase64String(env.SignatureBase64), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new CryptographicException("Подпись пакета неверна");
        return payload;
    }
}
