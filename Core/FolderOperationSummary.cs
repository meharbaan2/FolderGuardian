namespace FolderGuardian.Core;

internal sealed record FolderOperationSummary(
    int ProcessedCount,
    int SkippedCount,
    int FailedCount,
    int TotalCount,
    TimeSpan Duration);
