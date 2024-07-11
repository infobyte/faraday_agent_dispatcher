def severity_from_score(score: float, max_score: float):
    """
    Returns severity string from score range.

    >> [score]     - input score value

    >> [max_score] - could be 10 or 100 (or whatever, calc is proportional)

    << [severity]  - severity as string "info", "low", "medium", "high" or "critical"
    """
    if 0 <= score < max_score * 0.1:
        return "info"
    if max_score * 0.1 <= score < max_score * 0.4:
        return "low"
    if max_score * 0.4 <= score < max_score * 0.7:
        return "medium"
    if max_score * 0.7 <= score < max_score * 0.9:
        return "high"
    if max_score * 0.9 <= score <= max_score:
        return "critical"
    return "unclassified"
