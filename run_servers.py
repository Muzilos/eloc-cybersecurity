import os
import glob
import importlib.util
from flask import Flask, Response
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# Navigation buttons CSS and JavaScript
NAV_STYLES = """
<style>
    .challenge-nav {
        position: fixed;
        bottom: 20px;
        right: 20px;
        display: flex;
        gap: 10px;
        z-index: 1000;
    }
    .challenge-nav a {
        padding: 8px 16px;
        background: #0066cc;
        color: white;
        text-decoration: none;
        border-radius: 4px;
        font-family: system-ui, -apple-system, sans-serif;
        transition: background 0.2s;
    }
    .challenge-nav a:hover {
        background: #0052a3;
    }
    .challenge-nav a.disabled {
        background: #ccc;
        pointer-events: none;
    }
</style>
"""

def create_nav_buttons(current_dir, all_dirs):
    """Create navigation buttons HTML based on current directory"""
    sorted_dirs = sorted(all_dirs)
    current_idx = sorted_dirs.index(current_dir)
    
    prev_link = ''
    next_link = ''
    
    if current_idx > 0:
        prev_dir = sorted_dirs[current_idx - 1]
        prev_link = f'<a href="/{prev_dir}">← Previous Challenge</a>'
    
    if current_idx < len(sorted_dirs) - 1:
        next_dir = sorted_dirs[current_idx + 1]
        next_link = f'<a href="/{next_dir}">Next Challenge →</a>'
    
    return f'<div class="challenge-nav">{prev_link}{next_link}</div>'

# JavaScript to inject into HTML responses
def get_prefix_and_nav_js(current_dir, all_dirs):
    return f"""
{NAV_STYLES}
<script>
    // Store the original fetch function
    const originalFetch = window.fetch;
    
    // Get the app prefix from the current URL path
    const appPrefix = window.location.pathname.split('/')[1];
    
    // Override fetch to automatically add the prefix
    window.fetch = function(url, options) {{
        if (url.startsWith('/') && !url.startsWith(`/${{appPrefix}}/`)) {{
            url = `/${{appPrefix}}${{url}}`;
        }}
        return originalFetch(url, options);
    }};
</script>
{create_nav_buttons(current_dir, all_dirs)}
"""

def wrap_app_with_prefix_handler(app, prefix, all_dirs):
    """Wrap a Flask app with middleware to inject the prefix handler JS and nav buttons"""
    
    @app.after_request
    def inject_prefix_handler(response: Response):
        if response.content_type and 'text/html' in response.content_type.lower():
            content = response.get_data(as_text=True)
            
            # Create the combined JS and nav buttons for this specific directory
            inject_content = get_prefix_and_nav_js(prefix, all_dirs)
            
            # Insert our content just before the closing </body> tag
            if '</body>' in content:
                content = content.replace('</body>', f'{inject_content}</body>')
            else:
                content += inject_content
                
            response.set_data(content)
        return response
    
    return app

def import_server_module(server_path):
    """Import a server.py file as a module properly."""
    dir_name = os.path.basename(os.path.dirname(server_path))
    module_name = f"server_{dir_name}"
    
    spec = importlib.util.spec_from_file_location(module_name, server_path)
    module = importlib.util.module_from_spec(spec)
    
    try:
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"Error loading {server_path}: {e}")
        return None

# Create main app
app = Flask(__name__)

# Find all server.py files and get their directory names
base_dir = os.path.dirname(os.path.abspath(__file__))
server_files = glob.glob(os.path.join(base_dir, '*/server.py'))
all_dirs = [os.path.basename(os.path.dirname(path)) for path in server_files]

# Dictionary to hold our mounted apps
mounts = {}

# Import and mount each app
for server_path in server_files:
    dir_name = os.path.basename(os.path.dirname(server_path))
    print(f"Loading {dir_name}...")
    
    # Change to server's directory before importing
    original_dir = os.getcwd()
    os.chdir(os.path.dirname(server_path))
    
    try:
        # Import the module properly
        module = import_server_module(server_path)
        if module and hasattr(module, 'app'):
            # Wrap the app with our prefix handler and navigation
            wrapped_app = wrap_app_with_prefix_handler(module.app, dir_name, all_dirs)
            mounts[f'/{dir_name}'] = wrapped_app
            print(f"Mounted /{dir_name}")
        else:
            print(f"Skipping {dir_name} - no Flask app found")
    except Exception as e:
        print(f"Error mounting {dir_name}: {e}")
    finally:
        # Always restore the original directory
        os.chdir(original_dir)

# Create the unified application
application = DispatcherMiddleware(Flask(__name__), mounts)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    print("\nStarting unified server...")
    print("Mounted routes:")
    for route in sorted(mounts.keys()):
        print(f"  {route}")
    run_simple('0.0.0.0', 5000, application, use_reloader=True)