from __future__ import annotations

import os

from knives_out.auth_plugins import PreparedRequest, RuntimeContext, RuntimePlugin, make_auth_plugin


class EnvBearerPlugin(RuntimePlugin):
    def before_request(self, request: PreparedRequest, context: RuntimeContext) -> None:
        del context
        token = os.environ.get("KNIVES_OUT_BEARER_TOKEN")
        if not token:
            raise RuntimeError(
                "Set KNIVES_OUT_BEARER_TOKEN before using the 'env-bearer' auth plugin."
            )
        request.headers.setdefault("Authorization", f"Bearer {token}")


auth_plugin = make_auth_plugin("env-bearer", EnvBearerPlugin())
