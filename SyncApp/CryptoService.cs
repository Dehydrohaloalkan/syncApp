using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Globalization;
using Age;
using Age.Recipients;

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
    public Task<SecretKeys> Generate(string? workspaceRoot = null)
    {
        var (identity, recipient) = GenerateAgeIdentity();
        using var rsa = RSA.Create(3072);
        var keys = new SecretKeys { AgeIdentity = identity, AgeRecipient = recipient, SigningPrivatePem = rsa.ExportRSAPrivateKeyPem(), SigningPublicPem = rsa.ExportSubjectPublicKeyInfoPem() };
        return Task.FromResult(keys);
    }

    public Task<SecretKeys> GenerateAgeOnly(string? workspaceRoot = null)
    {
        var (identity, recipient) = GenerateAgeIdentity();
        return Task.FromResult(new SecretKeys { AgeIdentity = identity, AgeRecipient = recipient });
    }

    private static (string Identity, string Recipient) GenerateAgeIdentity()
    {
        using var ageIdentity = AgeKeygen.Generate();
        var recipient = ageIdentity.Recipient.ToString();
        var createdAt = DateTimeOffset.Now.ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);
        var identity = $"# created: {createdAt}\n# public key: {recipient}\n{ageIdentity.ToSecretString()}\n";
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

    public Task<byte[]> Protect(byte[] payload, string recipient, SecretKeys signer)
    {
        using var rsa = RSA.Create(); rsa.ImportFromPem(signer.SigningPrivatePem);
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new SignedEnvelope { PayloadBase64 = Convert.ToBase64String(payload), SignatureBase64 = Convert.ToBase64String(signature), SigningKey = signer.SigningPublicPem }, JsonConfig.Options);
        try
        {
            var ageRecipient = ParseAgeRecipient(recipient);
            using var input = new MemoryStream(envelope, writable: false);
            using var encrypted = new MemoryStream();
            AgeEncrypt.Encrypt(input, encrypted, ageRecipient);
            return Task.FromResult(encrypted.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    public Task<byte[]> Open(byte[] ciphertext, SecretKeys recipient, string? pinnedSigner, string? expectedFingerprint = null, string? workspaceRoot = null)
    {
        using var ageIdentity = ParseAgeIdentity(recipient.AgeIdentity);
        using var input = new MemoryStream(ciphertext, writable: false);
        using var decrypted = new MemoryStream(ciphertext.Length);
        try
        {
            try
            {
                AgeEncrypt.Decrypt(input, decrypted, ageIdentity);
            }
            catch (AgeException exception)
            {
                throw new CryptographicException("Не удалось расшифровать age-пакет", exception);
            }

            var plain = decrypted.ToArray();
            try
            {
                var env = JsonSerializer.Deserialize<SignedEnvelope>(plain, JsonConfig.Options)
                    ?? throw new InvalidDataException("Некорректный контейнер");
                if (env.Version != 1)
                    throw new NotSupportedException("Версия контейнера не поддерживается");

                if (pinnedSigner != null && !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(env.SigningKey), Encoding.UTF8.GetBytes(pinnedSigner)))
                    throw new CryptographicException("Подпись другого устройства");

                if (pinnedSigner == null && (expectedFingerprint == null || !string.Equals(
                    expectedFingerprint, Fingerprint(env.SigningKey), StringComparison.OrdinalIgnoreCase)))
                    throw new CryptographicException("Отпечаток отправителя не подтверждён");

                var payload = Convert.FromBase64String(env.PayloadBase64);
                using var rsa = RSA.Create();
                rsa.ImportFromPem(env.SigningKey);
                var signature = Convert.FromBase64String(env.SignatureBase64);
                if (!rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                    throw new CryptographicException("Подпись пакета неверна");

                CryptographicOperations.ZeroMemory(signature);
                return Task.FromResult(payload);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted.GetBuffer().AsSpan(0, (int)decrypted.Length));
        }
    }

    private static X25519Recipient ParseAgeRecipient(string recipient)
    {
        try
        {
            return AgeKeygen.ParseRecipient(recipient);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Некорректный публичный age-ключ", exception);
        }
    }

    private static X25519Identity ParseAgeIdentity(string identityText)
    {
        var identityLines = new List<string>();
        foreach (var line in identityText.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith('#'))
                continue;

            if (!line.StartsWith("AGE-SECRET-KEY-1", StringComparison.Ordinal))
                throw new InvalidDataException("Файл age-ключа повреждён");

            identityLines.Add(line);
        }

        if (identityLines.Count != 1)
            throw new InvalidDataException("Файл age-ключа повреждён");

        try
        {
            return AgeKeygen.ParseIdentity(identityLines[0]);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Файл age-ключа повреждён", exception);
        }
    }
}
