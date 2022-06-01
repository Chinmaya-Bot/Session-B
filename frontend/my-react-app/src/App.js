import logo from './logo.svg';
import './App.css';
import React from 'react';
import {useState} from 'react';
import SourceIp from './components/SourceIp';

function UploadFile(){
  const [file,setFile] = useState("")
  function uplad(){
    let headers = new Headers()
    headers.append('Access-Control-Allow-Origin', 'http://localhost:3000');
headers.append('Access-Control-Allow-Credentials', 'true');
    console.log(file,"1")
    const formData = new FormData();
    formData.append('file',file);
    let result =  fetch("http://127.0.0.1:5000/file-upload",{
      method:'POST',
      body:formData,
      headers:headers
    });
    alert("Data has been uploaded")
  }
  return(
    <div>
      <input type="file"
      onChange={(e)=>setFile(e.target.files[0])}></input>
      <button onClick={uplad}> Submit</button>
      <SourceIp />
    </div>
  )
}

export default UploadFile;
