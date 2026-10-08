"""Q1 — SQL Injection challenge (Set B, easier): the Birchwood storefront.

Birchwood is a full home-goods store: browse, search, product pages with specs
& reviews, a working cart → checkout → order flow, and newsletter/contact forms.
Everything is safe and parameterized EXCEPT the product **search**, which builds
its SQL by string concatenation — the single intentional vulnerability.

The Q1 flag is an ordinary, unlisted product row (`hidden=1` in `products`) that
every normal listing query filters out — including the vulnerable search, which
applies the same filter. Because the search is built by concatenation, a `-- `
comment in the payload truncates the query and drops that trailing filter,
surfacing the hidden row. No second table, no UNION, no column-matching —
just breaking out of the string and commenting out the rest.

Intentionally vulnerable code for an authorised training contest — do not fix
the search query.
"""
from flask import (Blueprint, request, render_template, redirect, url_for,
                   session, flash, abort)

from .. import db

bp = Blueprint("shop", __name__, url_prefix="/shop")

PER_PAGE = 8
SORTS = {
    "featured": "Featured",
    "price_asc": "Price: low to high",
    "price_desc": "Price: high to low",
    "rating": "Top rated",
    "newest": "Newest",
}


# --- helpers --------------------------------------------------------------

def _sort_key(items, sort):
    def num(v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default
    if sort == "price_asc":
        return sorted(items, key=lambda p: num(p.get("price")))
    if sort == "price_desc":
        return sorted(items, key=lambda p: num(p.get("price")), reverse=True)
    if sort == "rating":
        return sorted(items, key=lambda p: num(p.get("rating")), reverse=True)
    if sort == "newest":
        return sorted(items, key=lambda p: num(p.get("id")), reverse=True)
    return items  # featured = natural order


def _paginate(items, page):
    total = len(items)
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = max(1, min(page, pages))
    start = (page - 1) * PER_PAGE
    return items[start:start + PER_PAGE], page, pages, total


def _page_arg():
    try:
        return int(request.args.get("page", 1))
    except (TypeError, ValueError):
        return 1


def _cart():
    return session.get("cart", {})


def _save_cart(cart):
    session["cart"] = cart
    session.modified = True


def _cart_items():
    cart = _cart()
    ids = []
    for k in cart:
        try:
            ids.append(int(k))
        except ValueError:
            continue
    products = db.products_by_ids(ids)
    items, subtotal = [], 0.0
    for p in products:
        qty = int(cart.get(str(p["id"]), 0))
        if qty <= 0:
            continue
        line = p["price"] * qty
        subtotal += line
        items.append({**p, "qty": qty, "line": line})
    return items, subtotal


# --- storefront -----------------------------------------------------------

@bp.route("/", strict_slashes=False)
def index():
    q = request.args.get("q")
    category = request.args.get("category")
    sort = request.args.get("sort", "featured")
    if sort not in SORTS:
        sort = "featured"
    categories = db.list_categories()

    # Search — INTENTIONALLY VULNERABLE.
    if q is not None:
        rows, error = db.search_products(q)
        results = None
        page = pages = total = 0
        if rows is not None:
            ordered = _sort_key(rows, sort)
            results, page, pages, total = _paginate(ordered, _page_arg())
        return render_template("shop/search.html", q=q, results=results,
                               error=error, sort=sort, sorts=SORTS,
                               page=page, pages=pages, total=total,
                               categories=categories)

    # Category browse — SAFE.
    if category:
        cat_name, rows = db.category_products(category)
        if cat_name is None:
            abort(404)
        if request.args.get("in_stock") == "1":
            rows = [p for p in rows if p.get("stock", 0) > 0]
        ordered = _sort_key(rows, sort)
        page_items, page, pages, total = _paginate(ordered, _page_arg())
        return render_template("shop/browse.html", heading=cat_name,
                               products=page_items, categories=categories,
                               active=category, sort=sort, sorts=SORTS,
                               page=page, pages=pages, total=total,
                               in_stock=request.args.get("in_stock") == "1")

    # Home.
    return render_template("shop/home.html", featured=db.featured_products(8),
                           categories=categories)


@bp.route("/product/<int:pid>")
def product(pid):
    item = db.get_product(pid)          # SAFE (parameterized)
    if item is None:
        abort(404)
    specs = [
        ("SKU", f"BWD-{item['id']:04d}"),
        ("Category", item["category"]),
        ("Rating", f"{item['rating']} / 5"),
        ("Care", "Handmade — see care card included with order"),
        ("Availability", "In stock" if item["stock"] > 0 else "Out of stock"),
    ]
    return render_template("shop/product.html", item=item, specs=specs,
                           reviews=db.reviews_for(pid),
                           related=db.related_products(item["category"], item["id"]),
                           categories=db.list_categories())


# --- cart -----------------------------------------------------------------

@bp.route("/cart")
def cart():
    items, subtotal = _cart_items()
    return render_template("shop/cart.html", items=items, subtotal=subtotal,
                           categories=db.list_categories())


@bp.route("/cart/add", methods=["POST"])
def cart_add():
    pid = request.form.get("product_id", "")
    try:
        qty = max(1, int(request.form.get("qty", 1)))
    except ValueError:
        qty = 1
    item = db.get_product(int(pid)) if pid.isdigit() else None
    if not item:
        abort(404)
    cart = _cart()
    cart[str(item["id"])] = cart.get(str(item["id"]), 0) + qty
    _save_cart(cart)
    flash(f"Added {item['name']} to your cart.", "success")
    return redirect(url_for("shop.cart"))


@bp.route("/cart/update", methods=["POST"])
def cart_update():
    pid = request.form.get("product_id", "")
    try:
        qty = int(request.form.get("qty", 0))
    except ValueError:
        qty = 0
    cart = _cart()
    if pid in cart:
        if qty <= 0:
            cart.pop(pid)
            flash("Item removed.", "success")
        else:
            cart[pid] = qty
            flash("Cart updated.", "success")
        _save_cart(cart)
    return redirect(url_for("shop.cart"))


@bp.route("/cart/remove", methods=["POST"])
def cart_remove():
    pid = request.form.get("product_id", "")
    cart = _cart()
    if pid in cart:
        cart.pop(pid)
        _save_cart(cart)
        flash("Item removed.", "success")
    return redirect(url_for("shop.cart"))


# --- checkout -------------------------------------------------------------

@bp.route("/checkout", methods=["GET", "POST"])
def checkout():
    items, subtotal = _cart_items()
    if not items:
        flash("Your cart is empty.", "error")
        return redirect(url_for("shop.cart"))

    if request.method == "POST":
        fields = {k: request.form.get(k, "").strip()
                  for k in ("full_name", "email", "address", "city", "postcode")}
        missing = [k for k, v in fields.items() if not v]
        if missing:
            flash("Please fill in all fields.", "error")
            return render_template("shop/checkout.html", items=items,
                                   subtotal=subtotal, form=fields,
                                   categories=db.list_categories())
        number = db.create_order(
            fields["email"], fields["full_name"], fields["address"],
            fields["city"], fields["postcode"], items, subtotal)
        _save_cart({})  # empty the cart
        return redirect(url_for("shop.order", number=number))

    return render_template("shop/checkout.html", items=items, subtotal=subtotal,
                           form={}, categories=db.list_categories())


@bp.route("/order/<number>")
def order(number):
    order_row, items = db.get_order(number)
    if order_row is None:
        abort(404)
    return render_template("shop/order.html", order=order_row, items=items,
                           categories=db.list_categories())


# --- decoy forms + static pages ------------------------------------------

@bp.route("/newsletter", methods=["POST"])
def newsletter():
    email = request.form.get("email", "").strip()
    if "@" in email and "." in email:
        db.add_newsletter(email)
        flash("Thanks for subscribing!", "success")
    else:
        flash("Please enter a valid email address.", "error")
    return redirect(url_for("shop.index"))


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        if name and "@" in email and message:
            db.add_contact_message(name, email, message)
            flash("Thanks — we'll get back to you shortly.", "success")
            return redirect(url_for("shop.contact"))
        flash("Please complete all fields with a valid email.", "error")
    return render_template("shop/contact.html", categories=db.list_categories())


@bp.route("/about")
def about():
    return render_template("shop/about.html", categories=db.list_categories())


@bp.route("/shipping")
def shipping():
    return render_template("shop/page.html", title="Shipping",
                           body="We ship worldwide within 2–5 business days. "
                                "Free shipping on orders over $75.",
                           categories=db.list_categories())


@bp.route("/returns")
def returns():
    return render_template("shop/page.html", title="Returns",
                           body="Not happy? Return any item within 30 days for a "
                                "full refund. Items must be in original condition.",
                           categories=db.list_categories())
