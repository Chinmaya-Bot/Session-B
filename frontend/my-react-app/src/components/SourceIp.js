import React, {Component} from "react";
import axios from 'axios'


class SourceIp extends Component{
    constructor(props){
        super(props)
        this.state = {
            ips: [],
            nResults: 10,
            endpoint: "srcip"


        }
    }

     handleSubmit = (e) => {
        e.preventDefault()
        axios.get(`http://127.0.0.1:5000/${this.state.endpoint}/${this.state.nResults}`)
        .then((response)=>{
            console.log(response.data)

            this.setState({ips:response.data.details})
            // console.log(this.state)
        })
        .catch(error => {
            console.log(error)
        })
    }
    // componentDidMount(){
    //     axios.get('http://127.0.0.1:5000/srcip/10')
    //     .then((response)=>{
    //         console.log(response.data)

    //         this.setState({ips:response.data.srcip_details})
    //         // console.log(this.state)
    //     })
    //     .catch(error => {
    //         console.log(error)
    //     })
    // }
    render() {
        // const { ips } = this.state
        // console.log(ips.srcip_details)
        let lastKey
        if (this.state.ips.length > 0){

            const keysArray = Object.keys(this.state.ips[0])
            // remove connection
            keysArray.splice(keysArray.indexOf("connection"), 1)
            //remove percentage
            keysArray.splice(keysArray.indexOf("percentage"), 1)
            lastKey = keysArray[0]
        }

        return (
            <div>
            <div>
                <button onClick={() => this.setState({endpoint: "srcip"})}>srcip</button>
                <button onClick={() => this.setState({endpoint: "dstip"})}>dstip</button>
                <button onClick={() => this.setState({endpoint: "srcport"})}>srcport</button>
                <button onClick={() => this.setState({endpoint: "dstport"})}>dstport</button>
            </div>
            <form onSubmit={this.handleSubmit}>
                <input type="number" value={this.state.nResults} onChange={e => this.setState({nResults: e.target.value})} />
                <input type="submit" />
            </form>

                List of {this.state.endpoint}

                {
                    this.state.ips.length > 0 ?
                    this.state.ips.map((ip,index) => <div key={index}>
                    {ip.connections}, {ip.percentage}, {ip[lastKey]}
                     </div>) :
                     <div>No lines captured</div>
                }
            </div>
        )
    }
}

export default SourceIp
