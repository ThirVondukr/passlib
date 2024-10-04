def validate_rounds(rounds: int, min: int, max: int) -> None:
    if rounds < min or rounds > max:
        msg = f"rounds must be between {min} - {max}"
        raise ValueError(msg)
