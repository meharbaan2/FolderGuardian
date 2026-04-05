namespace FolderGuardian.Core;

internal sealed record FolderOperationProgress(
    string Phase,
    string? CurrentItem,
    int CompletedCount,
    int TotalCount,
    int FailedCount,
    TimeSpan? EstimatedRemaining);
