namespace AspNetCoreIdentity.MongoDriver.Mongo;

/// <summary>
/// Runs one-time store initialization (schema migrations and index creation) lazily, the
/// first time a store touches the database, instead of synchronously during service
/// registration. A failed attempt is not cached, so a transient connection problem at
/// startup is retried on the next store operation.
/// </summary>
public sealed class MongoIdentityInitializer
{
    private readonly Func<CancellationToken, Task> _initialize;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile bool _initialized;

    internal MongoIdentityInitializer(Func<CancellationToken, Task> initialize)
    {
        _initialize = initialize;
    }

    /// <summary>
    /// Ensures migrations and indexes have been applied. Safe to call concurrently; only the
    /// first caller does the work. Can be awaited at application startup to warm up eagerly.
    /// </summary>
    public async Task EnsureInitializedAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_initialized)
            {
                return;
            }

            await _initialize(cancellationToken).ConfigureAwait(false);
            _initialized = true;
        }
        finally
        {
            _gate.Release();
        }
    }
}
