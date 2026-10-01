import re
with open('app/routers/records_router.py', encoding='utf-8') as f:
    content = f.read()
routes = re.findall(r'@router\.(get|post|put|delete)\s*\(\s*["\']([^"\']*)["\']', content)
print('Ordem das rotas:')
for i, (method, path) in enumerate(routes, 1):
    print('  ' + str(i) + '. ' + method.upper() + ' /records' + path)
