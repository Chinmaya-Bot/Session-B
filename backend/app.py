from crypt import methods
from lib2to3 import pytree
import os
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from srx_cli import openconfig, analyze_session_table
from werkzeug.utils import secure_filename
from flask_parameter_validation import ValidateParameters, Route
import pytest

path = "./upload"
ALLOWED_EXTENSIONS = {'txt',}
file_path = ''

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = path
CORS(app)

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = path
    CORS(app)


    @app.route('/',methods=['GET','POST'])
    def hello():
        return {'message':'Backend Server'}

    def allowed_file(filename):
        return '.' in filename and \
            filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

    def allowed_file_content(file_path_name):
        with open(file_path_name,"r") as sessiondata:
            data = sessiondata.readlines()
        for connections in data:
            if re.search("Session ID:",connections) or re.search("In:",connections) or re.search("Out:",connections):
                global file_path 
                file_path = file_path_name
                resp = jsonify({'message' : 'File successfully uploaded'})
                resp.status_code = 201
                return resp
            else:
                #print("Deleting the file")
                #print(os.listdir(app.config['UPLOAD_FOLDER']))

                os.remove(file_path_name)

                #print(os.listdir(app.config['UPLOAD_FOLDER']))
                resp = jsonify({'message' : 'File contents are not allowed'})
                resp.status_code = 400
                return resp



    @app.route('/file-upload',methods=['POST'])
    def upload_file():
        # check if the post request has the file part
        if 'file' not in request.files:
            print(request.files[0])
            resp = jsonify({'message' : 'No file part in the request'})
            resp.status_code = 400
            return resp
        file = request.files['file']
        
        if file.filename == '':
            resp = jsonify({'message' : 'No file selected for uploading'})
            resp.status_code = 400
            return resp
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            resp = allowed_file_content(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return resp
            
        else:
            resp = jsonify({'message' : 'Allowed file type is txt'})
            resp.status_code = 400
            return resp


    @app.route('/srcip/<index>',methods =['GET'])
    def return_srcip(index):
    # if request.method == 'GET':
            #if 'index' not in request.args:
            #    resp = jsonify({'message' : 'Need an index'})
            #    resp.status_code = 400
            #    return resp
        
        #index = int(index)
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "srcip"
                sessiondata = openconfig(file_path)
                src_ip_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'srcip_details': src_ip_json})
                resp.status_code = 201
                return resp                
    #  else:
    #      resp = jsonify({'message' : 'Operation Not allowed'})
    #      resp.status_code = 400
    #     return resp


    @app.route('/dstip/<index>',methods =['GET'])
    def return_dstip(index):
    #  if request.method == 'POST':
            #if 'index' not in request.form:
            #    resp = jsonify({'message' : 'Need an index'})
            #    resp.status_code = 400
            #    return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "dstip"
                sessiondata = openconfig(file_path)
                dest_ip_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'dstip_details': dest_ip_json})
                resp.status_code = 201
                return resp                
    #  else:
    #      resp = jsonify({'message' : 'Operation Not allowed'})
    #      resp.status_code = 400
    #      return resp

    @app.route('/srcport/<index>',methods =['GET'])
    def return_srcport(index):
    # if request.method == 'POST':
        #    if 'index' not in request.form:
        #        resp = jsonify({'message' : 'Need an index'})
        #        resp.status_code = 400
        #        return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "srcport"
                sessiondata = openconfig(file_path)
                src_port_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'srcport_details': src_port_json})
                resp.status_code = 201
                return resp                
        #else:
        #    resp = jsonify({'message' : 'Operation Not allowed'})
        #    resp.status_code = 400
        #    return resp

    @app.route('/dstport/<index>',methods =['GET'])
    def return_dstport(index):
        # if request.method == 'POST':
        #     if 'index' not in request.form:
        #         resp = jsonify({'message' : 'Need an index'})
        #         resp.status_code = 400
        #         return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "dstport"
                sessiondata = openconfig(file_path)
                dst_port_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'dstport_details': dst_port_json})
                resp.status_code = 201
                return resp                
        # else:
        #     resp = jsonify({'message' : 'Operation Not allowed'})
        #     resp.status_code = 400
        #     return resp

    @app.route('/test',methods=['GET'])
    def return_test():
        return {'policy':"success"}


    @app.route('/protocol/<index>',methods =['GET'])
    def return_protocol(index):
        # if request.method == 'POST':
        #     if 'index' not in request.form:
        #         resp = jsonify({'message' : 'Need an index'})
        #         resp.status_code = 400
        #         return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "protocol"
                sessiondata = openconfig(file_path)
                protocol_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'protocol_details':protocol_json})
                resp.status_code = 201
                return resp                
        # else:
        #     resp = jsonify({'message' : 'Operation Not allowed'})
        #     resp.status_code = 400
        #     return resp

    @app.route('/policy/<index>',methods =['GET'])
    def return_policy(index):
        # if request.method == 'POST':
        #     if 'index' not in request.form:
        #         resp = jsonify({'message' : 'Need an index'})
        #         resp.status_code = 400
        #         return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "policy"
                sessiondata = openconfig(file_path)
                policy_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'policy_details':policy_json})
                resp.status_code = 201
                return resp                
        # else:
        #     resp = jsonify({'message' : 'Operation Not allowed'})
        #     resp.status_code = 400
        #     return resp

    @app.route('/interface/<index>',methods =['GET'])
    def return_interface(index):
        # if request.method == 'POST':
        #     if 'index' not in request.form:
        #         resp = jsonify({'message' : 'Need an index'})
        #         resp.status_code = 400
        #         return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp

        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "interface"
                sessiondata = openconfig(file_path)
                interface_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'interface_details':interface_json})
                resp.status_code = 201
                return resp                
        # else:
        #     resp = jsonify({'message' : 'Operation Not allowed'})
        #     resp.status_code = 400
        #     return resp

    @app.route('/packets/<index>',methods =['GET'])
    def return_packets(index):
        # if request.method == 'POST':
        #     if 'index' not in request.form:
        #         resp = jsonify({'message' : 'Need an index'})
        #         resp.status_code = 400
        #         return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp


        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0 '})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "packet"
                sessiondata = openconfig(file_path)
                packets_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'packets_details':packets_json})
                resp.status_code = 201
                return resp                
        # else:
        #     resp = jsonify({'message' : 'Operation Not allowed'})
        #     resp.status_code = 400
        #     return resp

    @app.route('/bytes/<index>',methods =['GET'])
    def return_bytes(index):
        # if request.method == 'POST':
        #     if 'index' not in request.form:
        #         resp = jsonify({'message' : 'Need an index'})
        #         resp.status_code = 400
        #         return resp
        try:
            index = int(index)
        except:
            resp = jsonify({'message' : 'String Not allowed '})
            resp.status_code = 400
            return resp


        if index == 0:
            resp = jsonify({'message' : 'Index cannot be 0'})
            resp.status_code = 400
            return resp

        if index:
            global file_path
            numdisplayed = index
            if file_path == '':
                resp = jsonify({'message' : 'File not uploaded'})
                resp.status_code = 400
                return resp
            else:
                resulttype = "bytes"
                sessiondata = openconfig(file_path)
                bytes_json=analyze_session_table(sessiondata,numdisplayed,resulttype)
                resp = jsonify({'bytes_details':bytes_json})
                resp.status_code = 201
                return resp                
        # else:
        #     resp = jsonify({'message' : 'Operation Not allowed'})
        #     resp.status_code = 400
        #     return resp
    
    return app

if __name__ =="__main__":
    app = create_app()
    app.run(debug=True)


