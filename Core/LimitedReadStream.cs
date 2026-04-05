using System.IO;

namespace FolderGuardian.Core;

internal sealed class LimitedReadStream : Stream
{
    private readonly Stream _innerStream;
    private long _remainingBytes;

    public LimitedReadStream(Stream innerStream, long length)
    {
        _innerStream = innerStream;
        _remainingBytes = length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _remainingBytes;

    public override long Position
    {
        get => 0;
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_remainingBytes <= 0)
        {
            return 0;
        }

        int allowedCount = (int)Math.Min(count, _remainingBytes);
        int read = _innerStream.Read(buffer, offset, allowedCount);
        _remainingBytes -= read;
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_remainingBytes <= 0)
        {
            return 0;
        }

        int allowedCount = (int)Math.Min(count, _remainingBytes);
        int read = await _innerStream.ReadAsync(buffer.AsMemory(offset, allowedCount), cancellationToken);
        _remainingBytes -= read;
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_remainingBytes <= 0)
        {
            return 0;
        }

        int allowedCount = (int)Math.Min(buffer.Length, _remainingBytes);
        int read = await _innerStream.ReadAsync(buffer[..allowedCount], cancellationToken);
        _remainingBytes -= read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
}
