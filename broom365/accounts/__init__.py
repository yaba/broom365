"""Account management (admins only): list, create, change role, reset password, delete."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.wrappers import Response

from ..auth import admin_required, current_account
from ..db import get_db
from ..services import accounts as svc

bp = Blueprint("accounts", __name__, url_prefix="/accounts")


def _page(error: str | None = None, form: dict[str, str] | None = None, status: int = 200) -> tuple[str, int]:
    me = current_account()
    return render_template("accounts.html", accounts=svc.list_accounts(get_db()), me=me, roles=svc.ROLES, error=error,
                           form=form or {}), status


@bp.get("")
@admin_required
def index() -> tuple[str, int]:
    return _page()


@bp.post("/add")
@admin_required
def add() -> Response | tuple[str, int]:
    username, role = request.form.get("username", "").strip(), request.form.get("role", "reader")
    if err := svc.create(get_db(), username, request.form.get("password", ""), role):
        return _page(err, {"username": username, "role": role}, 400)
    flash(f"Account {username.lower()} created. It must choose its own password at the first sign-in.")
    return redirect(url_for("accounts.index"))


@bp.post("/<int:account_id>/role")
@admin_required
def role(account_id: int) -> Response | tuple[str, int]:
    if err := svc.set_role(get_db(), account_id, request.form.get("role", "")):
        return _page(err, status=400)
    return redirect(url_for("accounts.index"))


@bp.post("/<int:account_id>/reset")
@admin_required
def reset(account_id: int) -> Response | tuple[str, int]:
    acc = svc.get(get_db(), account_id)
    if acc is None:
        return _page("Unknown account.", status=404)
    if err := svc.validate_password(request.form.get("password", ""), acc.username):
        return _page(err, status=400)
    svc.set_password(get_db(), account_id, request.form["password"], must_change=True)
    flash(f"Password of {acc.username} reset. It must be changed at the next sign-in.")
    return redirect(url_for("accounts.index"))


@bp.post("/<int:account_id>/delete")
@admin_required
def remove(account_id: int) -> Response | tuple[str, int]:
    me = current_account()
    if me is not None and me.id == account_id:
        return _page("You cannot delete your own account.", status=400)
    if err := svc.delete(get_db(), account_id):
        return _page(err, status=400)
    flash("Account deleted.")
    return redirect(url_for("accounts.index"))
