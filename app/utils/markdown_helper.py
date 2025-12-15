import markdown
import bleach

ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'code', 'pre', 'blockquote', 'a'
]

ALLOWED_ATTRS = {
    'a': ['href', 'title'],
    'code': ['class']
}

def markdown_to_safe_html(md_text: str) -> str:
    html = markdown.markdown(
        md_text,
        extensions=['extra', 'nl2br', 'sane_lists']
    )
    
    clean_html = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        strip=True
    )
    
    return clean_html
