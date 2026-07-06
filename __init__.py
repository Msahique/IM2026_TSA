"""TSA Server package.

Points the settings loader at THIS server's own variable_config.json, unless
IM_CONFIG_FILE is already set (e.g. a Kubernetes ConfigMap mount, or start_all).
Runs before any submodule reads configuration.
"""
import os

os.environ.setdefault(
    "IM_CONFIG_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "variable_config.json"),
)
