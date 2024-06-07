using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Channels;
using Serilog;
using Serilog.Core;
using ShellProgressBar;

namespace WebCrawler;

class Program
{
    private static readonly Logger Logger = new LoggerConfiguration()
        .WriteTo
        .File("log.txt", outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
        .CreateLogger();

    private static readonly object ProgressBarLock = new();
    private static ProgressBar? _progressBar;

    private record CertificateInfo
    (
        string Subject,
        string Issuer,
        string ExpirationDate,
        string Thumbprint,
        string KeyAlgorithm
    );

    private record DomainData
    (
        string Domain,
        string? Server,
        CertificateInfo? CertificateInfo,
        Dictionary<string, string> HttpHeaders
    );

    private static readonly Channel<DomainData> DataChannel = Channel.CreateUnbounded<DomainData>();

    private static readonly int WorkersCount = Environment.ProcessorCount * 16;

    // When all the channels are done writing, this barrier will make sure that they are 
    private static readonly Barrier CloseDataChannelBarrier = new(WorkersCount, _ => DataChannel.Writer.Complete());

    private static readonly Channel<string> DomainChannel = Channel.CreateUnbounded<string>();

    private static DateTime _start = DateTime.Now;
    private static int _processed;

    static async Task PersistenceWorker(FileInfo? redirectedOut)
    {
        var reader = DataChannel.Reader;
        using var stream = redirectedOut?.Open(FileMode.Append) ?? Console.OpenStandardOutput();
        using var writer = new StreamWriter(stream);
        writer.AutoFlush = true;
        try
        {
            while (await reader.WaitToReadAsync())
            {
                while (reader.TryRead(out var data))
                {
                    var json = JsonSerializer.Serialize(data);
                    await writer.WriteLineAsync(json);
                    _processed++;
                    lock (ProgressBarLock)
                    {
                        if (_progressBar != null)
                        {
                            var elapsed = DateTime.Now - _start;
                            double rate = _processed / elapsed.TotalMilliseconds;
                            double remaining = _progressBar.MaxTicks - _processed;
                            double timeRemaining = remaining / rate;
                            _progressBar.Tick(_processed, $"Processed {_progressBar.CurrentTick} / {_progressBar.MaxTicks} ({rate * 1000:F2} req/s)");
                            _progressBar.EstimatedDuration = TimeSpan.FromMilliseconds(timeRemaining);
                        }
                    }
                }
            }

            await writer.FlushAsync();
            await stream.FlushAsync();
        }
        catch (ChannelClosedException)
        {
            // The channel was closed. Np.
        }

        await writer.FlushAsync();
        await stream.FlushAsync();
    }

    static async Task<DomainData?> TryHttpsRequestAsync(HttpClient client, Channel<X509Certificate2?> certChannel, string prefix, string domain)
    {
        try
        {
            // We need to try two different approaches.
            // We need to investigate if the domain uses https or http.
            var httpsGetResponse = await client.GetAsync($"https://{prefix}{domain}");
            if (httpsGetResponse.IsSuccessStatusCode)
            {
                CertificateInfo? certInfo = default;
                if (await certChannel.Reader.WaitToReadAsync())
                {
                    if (certChannel.Reader.TryRead(out var cert) && cert != null)
                    {
                        certInfo = new CertificateInfo
                        (
                            cert.Subject,
                            cert.Issuer,
                            cert.GetExpirationDateString(),
                            cert.Thumbprint,
                            cert.GetKeyAlgorithm()
                        );
                    }
                }

                var headers = httpsGetResponse
                    .Headers
                    .ToDictionary(it => it.Key, it => string.Join(',', it.Value));
                var server = headers.GetValueOrDefault("server") ??
                             headers.GetValueOrDefault("Server") ??
                             headers.GetValueOrDefault("X-Powered-By");
                return new DomainData
                (
                    domain,
                    server,
                    certInfo,
                    headers
                );
            }
        }
        catch
        {
            // ignored
        }

        return null;
    }

    static async Task<DomainData?> TryHttpRequestAsync(HttpClient client, string prefix, string domain)
    {
        try
        {
            var httpGetResponse = await client.GetAsync($"http://{prefix}{domain}");
            if (httpGetResponse.IsSuccessStatusCode)
            {
                var headers = httpGetResponse
                    .Headers
                    .ToDictionary(it => it.Key, it => string.Join(',', it.Value));
                var server = headers.GetValueOrDefault("server") ??
                             headers.GetValueOrDefault("Server") ??
                             headers.GetValueOrDefault("X-Powered-By");
                return new DomainData
                (
                    domain,
                    server,
                    null,
                    headers
                );
            }
        }
        catch
        {
            // ignored
        }

        return null;
    }

    static async Task DomainWorker(int timeoutSeconds)
    {

        var handler = new HttpClientHandler();
        var certChannel = Channel.CreateBounded<X509Certificate2?>(1);
        handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
        {
            certChannel.Writer.TryWrite(cert);
            return true;
        };

        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
        var reader = DomainChannel.Reader;
        var writer = DataChannel.Writer;
        try
        {
            while (await reader.WaitToReadAsync())
            {
                while (reader.TryRead(out var domain))
                {
                    var start = DateTime.Now;
                    var noPrefixHttpsData = await TryHttpsRequestAsync(client, certChannel, "", domain);
                    if (noPrefixHttpsData != null)
                    {
                        await writer.WriteAsync(noPrefixHttpsData);
                        Logger.Information("Found information about '{domain}' using {transport} and no prefix", domain, "https");
                        continue;
                    }

                    var wwwPrefixHttpsData = await TryHttpsRequestAsync(client, certChannel, "www", domain);
                    if (wwwPrefixHttpsData != null)
                    {
                        await writer.WriteAsync(wwwPrefixHttpsData);
                        Logger.Information("Found information about '{domain}' using {transport} and prefix '{prefix}'", domain, "https", "www");
                        continue;
                    }

                    var noPrefixHttpData = await TryHttpRequestAsync(client, "", domain);
                    if (noPrefixHttpData != null)
                    {
                        await writer.WriteAsync(noPrefixHttpData);
                        Logger.Information("Found information about '{domain}' using {transport} and no prefix", domain, "http");
                        continue;
                    }

                    var wwwPrefixHttpData = await TryHttpRequestAsync(client, "www", domain);
                    if (wwwPrefixHttpData != null)
                    {
                        await writer.WriteAsync(wwwPrefixHttpData);
                        Logger.Information("Found information about '{domain}' using {transport} and prefix '{prefix}'", domain, "http", "www");
                        continue;
                    }
                    Logger.Error(exception: null, "Could not gather any information about '{domain}'", domain);
                    await writer.WriteAsync(new DomainData(domain, null, null, []));
                }
            }
        }
        catch (ChannelClosedException)
        {
            // Let the task end.
        }
        finally
        {
            certChannel.Writer.Complete();
            CloseDataChannelBarrier.SignalAndWait();
        }
    }

    static async Task<HashSet<string>> GetProcessedDomains(FileInfo? redirectedOut)
    {
        var existingDomains = new HashSet<string>();
        if (redirectedOut != null && redirectedOut.Exists)
        {
            using var stream = redirectedOut.OpenRead();
            using var streamReader = new StreamReader(stream);
            while (await streamReader.ReadLineAsync() is { } line)
            {
                try
                {
                    var domainData = JsonSerializer.Deserialize<DomainData?>(line);
                    if (domainData == null) continue;
                    existingDomains.Add(domainData.Domain);
                }
                catch { }
            }
        }
        return existingDomains;
    }

    static async Task Run(FileInfo? redirectedIn, FileInfo? redirectedOut, int timeoutSeconds)
    {
        var processedDomains = await GetProcessedDomains(redirectedOut);
        if (processedDomains.Any())
        {
            Logger.Information($"Skipping {processedDomains.Count} already checked domains.");
        }
        
        var persistenceWorker = new Thread(async () => await PersistenceWorker(redirectedOut));
        persistenceWorker.Start();
        var domainWorkers = Enumerable
            .Range(0, WorkersCount)
            .Select(_ => Task.Run(() => DomainWorker(timeoutSeconds)))
            .ToArray();

        var input = redirectedIn?.OpenRead() ?? Console.OpenStandardInput();
        using var streamReader = new StreamReader(input);
        var channelWriter = DomainChannel.Writer;
        await Console.Error.WriteLineAsync("Requesting domain data...");
        var total = 0;
        while (await streamReader.ReadLineAsync() is { } line)
        {
            var trimmed = line.Trim();
            if (processedDomains.Contains(trimmed)) continue;
            if (string.IsNullOrWhiteSpace(trimmed)) continue;
            await channelWriter.WriteAsync(trimmed);
            total++;
        }

        channelWriter.Complete();
        await Console.Error.WriteLineAsync($"Counted {total} domains to crawl.");
        lock (ProgressBarLock)
        {
            _progressBar = redirectedOut == null ? null : new ProgressBar
            (
                total,
                "Saving domain data...",
                new ProgressBarOptions { ShowEstimatedDuration = true }
            );
            _progressBar!.EstimatedDuration = TimeSpan.FromMilliseconds(total * 500);
        }

        await Task.WhenAll(domainWorkers);
        persistenceWorker.Join();
        if (_progressBar != null)
        {
            _progressBar.WriteErrorLine($"Succesfully crawled {_processed}/{total} domains.");
        }
        else
        {
            await Console.Error.WriteLineAsync($"Successfully crawled {_processed}/{total} domains.");
        }
    }

    static async Task Main(string[] args)
    {
        var dataPath = new Option<FileInfo?>
            ("--input", () => null, "Sets an input file instead of reading from stdin (windows friendly)");
        dataPath.AddAlias("-i");
        var outputPath = new Option<FileInfo?>("--output", () => null, "The output path for the collected data.");
        outputPath.AddAlias("-o");
        var timeout = new Option<int>("--timeout", () => 5, "Timeout in seconds per request. Default is 5 seconds.");
        timeout.AddAlias("-t");
        var rootCommand = new RootCommand
        (
            "Crawls a list of domains read from stdin and reports back some very basic info about each."
        );
        rootCommand.AddOption(outputPath);
        rootCommand.AddOption(dataPath);
        rootCommand.AddOption(timeout);
        rootCommand.SetHandler(Run, dataPath, outputPath, timeout);
        await rootCommand.InvokeAsync(args);
    }
}