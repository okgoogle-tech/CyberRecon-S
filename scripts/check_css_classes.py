import re
import glob

def check():
    css_classes = set()
    for path in glob.glob('CyberRecon-S/src/cyberrecon/static/css/**/*.css', recursive=True):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        matches = re.findall(r'\.([a-zA-Z0-9_\-]+)', content)
        for m in matches:
            css_classes.add(m)

    templates = ['index.html', 'dashboard.html', 'about.html']
    for t_name in templates:
        t_path = f'CyberRecon-S/src/cyberrecon/templates/{t_name}'
        with open(t_path, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()
        classes_in_template = set()
        for m in re.finditer(r'class=["\']([^"\']+)["\']', html):
            for c in m.group(1).split():
                if '{{' not in c and '{%' not in c:
                    classes_in_template.add(c)
        
        missing = [c for c in sorted(classes_in_template) if c not in css_classes]
        print(f"=== {t_name} ===")
        print(f"Total classes in markup: {len(classes_in_template)}, Missing in CSS: {len(missing)}")
        if missing:
            print(f"Missing classes ({len(missing)}): {missing}")

if __name__ == '__main__':
    check()
