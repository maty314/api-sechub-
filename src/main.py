import os
import io
import json
import requests
import re
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_sechub_engagements():
    sechub_url = os.environ.get('sechubURL')
    sechub_token = os.environ.get('sechubToken')
    product_id = os.environ.get('product')  # ID del producto
    headers = {'Authorization': f'Token {sechub_token}'}
    response = requests.get(f"{sechub_url}/api/v2/engagements/?product={product_id}", headers=headers)
    if response.status_code == 200:
        engagements_data = response.json()
        engagements = engagements_data.get('results', [])
        return engagements
    else:
        return None

def get_engagement_by_name(engagement_name):
    engagements = get_sechub_engagements()
    if engagements:
        for engagement in engagements:
            if engagement.get('name') == engagement_name:
                return engagement
    return None

def get_tests_by_engagement_id(engagement_id):
    sechub_url = os.environ.get('sechubURL')
    sechub_token = os.environ.get('sechubToken')
    headers = {'Authorization': f'Token {sechub_token}'}
    response = requests.get(f"{sechub_url}/api/v2/tests/?engagement={engagement_id}", headers=headers)
    if response.status_code == 200:
        tests_data = response.json()
        tests = tests_data.get('results', [])
        return tests
    else:
        return None

def engagement_has_tests(engagement_id):
    tests = get_tests_by_engagement_id(engagement_id)
    return bool(tests) if tests is not None else False

def create_sechub_engagement(engagement_name, product_id):
    sechub_url = os.environ.get('sechubURL')
    sechub_token = os.environ.get('sechubToken')
    today = datetime.now().strftime('%Y-%m-%d')
    next_year = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
    headers = {'Authorization': f'Token {sechub_token}'}
    data = {
        'name': engagement_name,
        'product': product_id,  # Usamos el ID del producto
        'target_start': today,
        'target_end': next_year
    }
    response = requests.post(f"{sechub_url}/api/v2/engagements/", headers=headers, data=data)
    print(f"POST Request Response: {response.status_code}, {response.text}")  # Debugging
    return response.status_code

def import_findings_to_engagement(report_data, engagement_name, product_name, report_name, import_type='import-scan'):
    sechub_url = os.environ.get('sechubURL')
    sechub_token = os.environ.get('sechubToken')    
    today = datetime.now().strftime('%Y-%m-%d')
    service_name = re.sub(r'-[0-9a-f]{5,}(-[0-9a-z]+)?', '', report_name)

    headers = {
        "Authorization": f"Token {sechub_token}",
        "accept": "application/json"
    }
    data = {
        "minimum_severity": "Critical",
        "active": True,
        "verified": True,
        "scan_type": "Trivy Operator Scan",
        "close_old_findings": True,
        "push_to_jira": False,
        "deduplication_on_engagement": True,
        "group_by": "component_name",
        "product_name": product_name,  # Usamos el nombre del producto
        "scan_date": today,
        "engagement_name": engagement_name,
        "service": service_name
    }
    files = {
        "file": report_data  
    }

    try:
        response = requests.post(
            f"{sechub_url}/api/v2/{import_type}/",
            headers=headers,
            data=data,
            files=files
        )
        print(f"POST Request Response: {response.status_code}, {response.text}")  # Debugging
        return (response.status_code, None) if response.ok else (response.status_code, response.text)
    except requests.RequestException as e:
        print(f"Error al realizar la solicitud: {e}")
        error_message = f"{e}"
        if hasattr(e, 'response') and e.response is not None:
            error_message += f" - Respuesta de error: {e.response.status_code}, {e.response.text}"
        return (None, error_message)

@app.route('/report', methods=['POST'])
def handle_report():
    data = request.json
    operatorObject = data['operatorObject']
    
    reportVerb = data.get('verb', 'No verb provided')
    reportData = operatorObject
    reportKind = operatorObject.get('kind', 'No kind provided')
    reportName = operatorObject.get('metadata', {}).get('name', 'No name provided')
    reportNamespace = operatorObject.get('metadata', {}).get('namespace', 'No namespace provided')

    # Obtener la operación del primer elemento en managedFields
    if 'managedFields' in operatorObject and len(operatorObject['managedFields']) > 0:
        reportOperation = operatorObject['managedFields'][0].get('operation', 'No operation provided')
    else:
        reportOperation = 'No managedFields provided'

    engagement = get_engagement_by_name(reportKind)

    # Si el engagement no existe, lo creamos
    if not engagement:
        print(f"Creando engagement para {reportKind}...")
        create_sechub_engagement(reportKind, os.environ.get('product'))
        print(f"Engagement para {reportKind} creado.")
        # Esperamos a que el engagement se cree
        time.sleep(1)
        engagement = get_engagement_by_name(reportKind)
        if not engagement:
            return jsonify({"status": "error", "message": f"Engagement {reportKind} could not be created"}), 500

    engagement_id = engagement.get('id')

    # Convertimos el objeto en JSON y lo pasamos como archivo
    report_data_json = json.dumps(operatorObject)
    report_data_file = io.StringIO(report_data_json)

    # Verificamos si el engagement ya tiene tests
    if engagement_has_tests(engagement_id):
        # Si ya tiene tests, usamos reimport-scan
        import_type = 'reimport-scan'
        print(f"Engagement {reportKind} ya tiene tests. Usando reimport-scan.")
    else:
        # Si no tiene tests, usamos import-scan
        import_type = 'import-scan'
        print(f"Engagement {reportKind} no tiene tests. Usando import-scan.")

    # Realizamos la importación o reimportación
    import_status, error_message = import_findings_to_engagement(
        report_data_file,
        reportKind,
        os.environ.get('productName'),  # Usamos el nombre del producto
        reportName,
        import_type=import_type
    )
    if import_status in [200, 201]:
        print("Importación de findings exitosa")
    else:
        print(f"Error al importar findings: {error_message}")

    return jsonify({
        "status": "success",
        "reportVerb": reportVerb,
        "reportData": reportData,
        "reportKind": reportKind,
        "reportName": reportName,
        "reportNamespace": reportNamespace,
        "reportOperation": reportOperation
    })

@app.route('/', methods=['GET'])
def health_check():
    return '', 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
