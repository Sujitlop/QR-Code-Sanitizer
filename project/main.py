from flask import Flask, request, jsonify, render_template, send_from_directory
import base64
import re
import os
from image_rec import analyze_qr_code, assess_qr_payload

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

@app.route('/upload_image', methods=['POST', 'OPTIONS'])
def upload_image():
    if request.method == 'OPTIONS':
        return ('', 204)

    try:
        data = request.get_json(silent=True) or {}

        # Extract base64 image data
        image_data = data.get('image')
        if not image_data:
            return jsonify({'status': 'failure', 'message': 'No image payload provided.'}), 400

        # Remove the image metadata (the "data:image/png;base64," prefix)
        image_data = re.sub('^data:image/.+;base64,', '', image_data)

        # Decode the image
        image = base64.b64decode(image_data)

        # Save the image in the uploads folder
        image_path = os.path.join(UPLOAD_FOLDER, 'captured_image.png')
        with open(image_path, 'wb') as f:
            f.write(image)

        # Analyze QR detection and payload safety
        analysis = analyze_qr_code(image_path)
        qr_present = analysis.get('detected', False)
        decoded_text = analysis.get('payload', '')

        safety = {
            'verdict': 'undetermined',
            'is_malicious': False,
            'risk_score': 0,
            'reasons': ['QR was detected but payload could not be decoded.'],
            'payload_type': 'unknown',
        }
        if qr_present and decoded_text:
            safety = assess_qr_payload(decoded_text)

        return jsonify({
            'status': 'success',
            'qr_code_detected': qr_present,
            'decoded_text': decoded_text,
            'safety': safety,
            'image_url': f'/uploads/captured_image.png'
        })
    except Exception as e:
        return jsonify({'status': 'failure', 'message': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)
