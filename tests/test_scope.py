from broom365.services.scope import parse_patterns


def m(text):
    return parse_patterns(text).matches


def test_prefix_wildcard_case_insensitive():
    f = m("win10-app-deployment*")
    assert f("win10-app-deployment-office") and f("WIN10-APP-DEPLOYMENT") and not f("win11-app-deployment-x")


def test_question_mark_matches_exactly_one_char():
    f = m("sales-emea-0?")
    assert f("sales-emea-01") and not f("sales-emea-010") and not f("sales-emea-0")


def test_no_wildcard_is_exact():
    f = m("Finance Team")
    assert f("finance team") and not f("Finance Team 2")


def test_exclude_overrides_include():
    f = m("win10-*\n!win10-app-deployment-test*")
    assert f("win10-vpn") and not f("win10-app-deployment-test-1")


def test_only_excludes_matches_nothing():
    assert not m("!foo*")("bar")


def test_empty_and_comments_ignored():
    f = m("# note\n\n  eng*  \n")
    assert f("Engineering") and not f("Sales")


def test_regex_metacharacters_are_literal():
    f = m("a.b[1]+(x)")
    assert f("a.b[1]+(x)") and not f("aXb1x")


def test_none_or_empty_name_never_matches():
    assert not m("*")(None) and not m("*")("")


def test_matches_any_uses_every_name_of_the_object():
    f = parse_patterns("partner-corp.com").matches_any
    assert f(["Pat Partner", "pat@partner-corp.com", "partner-corp.com"]) and not f(["Pat", "pat@other.com", "other.com"])
    g = parse_patterns("*@partner-corp.com").matches_any
    assert g(["Pat", "pat@partner-corp.com", "partner-corp.com"]) and not g(["Pat", None, "partner-corp.com"])


def test_matches_any_exclusion_wins_if_any_name_matches_it():
    f = parse_patterns("partner-corp.com\n!Pat*").matches_any
    assert not f(["Pat Partner", "pat@partner-corp.com", "partner-corp.com"])
    assert f(["Sue Second", "sue@partner-corp.com", "partner-corp.com"])


def test_matches_any_needs_an_include_and_ignores_empty_names():
    assert not parse_patterns("!x").matches_any(["x"]) and not parse_patterns("*").matches_any([None, ""])
