"""Sphinx configuration for pytempo."""

from pytempo import __version__

project = "pytempo"
copyright = "2025, Tempo"
author = "Tempo"
release = __version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
    "sphinx_copybutton",
    "myst_parser",
]

# -- General -------------------------------------------------------------------

exclude_patterns = ["_build"]
templates_path = ["_templates"]

# -- Autodoc -------------------------------------------------------------------

autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_class_signature = "separated"
always_use_bars_union = True

# -- Intersphinx ---------------------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "web3": ("https://web3py.readthedocs.io/en/stable", None),
}

# -- MyST (Markdown support) ---------------------------------------------------

myst_enable_extensions = [
    "colon_fence",
    "fieldlist",
]
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# -- HTML output ---------------------------------------------------------------

html_theme = "furo"
html_title = "pytempo"
html_static_path = ["_static"]

html_theme_options = {
    "source_repository": "https://github.com/tempoxyz/pytempo",
    "source_branch": "main",
    "source_directory": "docs/",
}
