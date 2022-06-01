import React, {Component} from "react";
import axios from 'axios'


class SourceIp extends Component{
    constructor(props){
        super(props)
        this.state = {
            ips: []
        }
    }
    componentDidMount(){
        axios.get('http://127.0.0.1:5000/srcip/10')
        .then((response)=>{
            
            this.setState({ips:response.data})
            // console.log(this.state)
        })
        .catch(error => {
            console.log(error)
        })
    }
    render() {
        // const { ips } = this.state
        // console.log(ips.srcip_details)
        return (
            <div>
                List of IPs
                
                {
                    this.state.ips.length ?
                    // ips[0].connections:
                    this.state.ips.map((ip,index) => <div key={index}>{ip.srcip_details.connections}
                     </div>) :
                    null
                }
            </div>
        )
    }
}

export default SourceIp