using System.Buffers;
using System.IO;
using System.Security.Cryptography;

namespace FolderGuardian.Core;

internal sealed class HashingWriteStream : Stream
{
    private readonly Stream _innerStream;
    private readonly HMAC _hmac;

    public HashingWriteStream(Stream innerStream, HMAC hmac)
    {
        _innerStream = innerStream;
        _hmac = hmac;
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _innerStream.Length;

    public override long Position
    {
        get => _innerStream.Position;
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        _innerStream.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return _innerStream.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        _innerStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (count <= 0)
        {
            return;
        }

        _hmac.TransformBlock(buffer, offset, count, null, 0);
        _innerStream.Write(buffer, offset, count);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (count <= 0)
        {
            return;
        }

        _hmac.TransformBlock(buffer, offset, count, null, 0);
        await _innerStream.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(buffer.Length);

        try
        {
            buffer.CopyTo(rented.AsMemory(0, buffer.Length));
            _hmac.TransformBlock(rented, 0, buffer.Length, null, 0);
            await _innerStream.WriteAsync(buffer, cancellationToken);
        }
        finally
        {
            Array.Clear(rented, 0, buffer.Length);
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
