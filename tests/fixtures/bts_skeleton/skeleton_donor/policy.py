"""Leitir-authored trusted donor fixture, deliberately inside BTS v1."""


def clamp(value, lower, upper):
    if value < lower:
        return lower
    if value > upper:
        return upper
    return value


def normalized_score(value, lower, upper):
    return clamp(value + 1, lower, upper)


# Padding keeps the included two-function source ratio at ADR-0008's bound.
# The fixture intentionally has no decorators, receivers, dynamic imports,
# registries, star imports, implicit resources, or environment dependencies.
# It is reviewed project test code, not an external donor execution sample.
# E4b can replace every donor-specific input while retaining the pipeline.
# End fixture metadata.
# Padding 01.
# Padding 02.
# Padding 03.
# Padding 04.
# Padding 05.
# Padding 06.
# Padding 07.
# Padding 08.
