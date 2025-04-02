from flask import Flask, render_template, request, jsonify
from password_analyzer import PasswordAnalyzer
import os
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

# Initialize the password analyzer
analyzer = PasswordAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.json.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    try:
        analysis = analyzer.analyze_password(password)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 