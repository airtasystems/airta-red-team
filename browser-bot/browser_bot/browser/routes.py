"""Resource blocking for Playwright routes."""

from browser_bot.config import BLOCKED_TYPES


def get_blocked_types(allow_styles: bool = False) -> set:
    """Types to block. When allow_styles=True, keep stylesheets for user-facing flows."""
    if allow_styles:
        return BLOCKED_TYPES - {"stylesheet"}
    return BLOCKED_TYPES


async def block_resources(route, blocked_types: set | None = None):
    """Block images, fonts, media, stylesheets to speed up loading."""
    types = blocked_types or BLOCKED_TYPES
    if route.request.resource_type in types:
        await route.abort()
    else:
        await route.continue_()
