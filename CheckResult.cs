namespace ProdMonitor;

/// <summary>Outcome of a single production check.</summary>
public sealed record CheckResult(string Name, bool Ok, string? Detail = null);
