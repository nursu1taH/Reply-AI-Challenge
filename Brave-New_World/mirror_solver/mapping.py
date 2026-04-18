from __future__ import annotations

import re
from functools import lru_cache
from difflib import SequenceMatcher

from .models import ResolvedIdentity, UserProfile


VOWELS = set("AEIOUY")


def _letters_only(value: str) -> str:
    return re.sub(r"[^A-Z]", "", value.upper())


def _consonant_signature(value: str) -> str:
    letters = _letters_only(value)
    consonants = "".join(char for char in letters if char not in VOWELS)
    return consonants or letters


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _segment_score(segment: str, value: str) -> float:
    cleaned_segment = _letters_only(segment)
    cleaned_value = _letters_only(value)
    signature = _consonant_signature(value)
    scores = [
        _similarity(cleaned_segment, cleaned_value),
        _similarity(cleaned_segment, signature),
        _similarity(signature, cleaned_segment),
    ]
    return max(scores)


def _account_match_score(account_id: str, user: UserProfile) -> float:
    parts = account_id.split("-")
    last_part = parts[0] if parts else ""
    first_part = parts[1] if len(parts) > 1 else ""
    city_part = parts[3] if len(parts) > 3 else ""
    last_score = _segment_score(last_part, user.last_name)
    first_score = _segment_score(first_part, user.first_name)
    city_score = _segment_score(city_part, user.residence_city)
    return (0.5 * last_score) + (0.3 * first_score) + (0.2 * city_score)


def resolve_identities(users: list[UserProfile], account_ids: list[str]) -> dict[str, ResolvedIdentity]:
    if not users or not account_ids:
        return {}

    unique_accounts = sorted(set(account_ids))
    if len(unique_accounts) != len(users):
        resolved: dict[str, ResolvedIdentity] = {}
        remaining_users = list(users)
        for account_id in unique_accounts:
            best_user = max(remaining_users, key=lambda user: _account_match_score(account_id, user))
            resolved[account_id] = ResolvedIdentity(
                account_id=account_id,
                user=best_user,
                score=_account_match_score(account_id, best_user),
            )
            remaining_users.remove(best_user)
        return resolved

    if len(unique_accounts) > 18:
        resolved: dict[str, ResolvedIdentity] = {}
        remaining_users = list(users)
        for account_id in unique_accounts:
            best_user = max(remaining_users, key=lambda user: _account_match_score(account_id, user))
            resolved[account_id] = ResolvedIdentity(
                account_id=account_id,
                user=best_user,
                score=_account_match_score(account_id, best_user),
            )
            remaining_users.remove(best_user)
        return resolved

    score_matrix = [
        [_account_match_score(account_id, user) for user in users]
        for account_id in unique_accounts
    ]

    @lru_cache(maxsize=None)
    def solve(account_index: int, used_mask: int) -> tuple[float, tuple[int, ...]]:
        if account_index == len(unique_accounts):
            return 0.0, ()

        best_total = float("-inf")
        best_assignment: tuple[int, ...] = ()
        for user_index in range(len(users)):
            if used_mask & (1 << user_index):
                continue
            score = score_matrix[account_index][user_index]
            downstream_total, downstream_assignment = solve(account_index + 1, used_mask | (1 << user_index))
            total = score + downstream_total
            if total > best_total:
                best_total = total
                best_assignment = (user_index,) + downstream_assignment
        return best_total, best_assignment

    _, assignment = solve(0, 0)
    resolved: dict[str, ResolvedIdentity] = {}
    for account_id, user_index, scores in zip(unique_accounts, assignment, score_matrix):
        resolved[account_id] = ResolvedIdentity(
            account_id=account_id,
            user=users[user_index],
            score=scores[user_index],
        )
    return resolved
