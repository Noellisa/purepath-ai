import "./Dashboard.css"
import { useState, useEffect } from "react";
import API_BASE_URL from "../../api";
import { useNavigate } from "react-router-dom"


export default function Dashboard() {
  const navigate = useNavigate();
  const [showAll, setShowAll] = useState(false);
const [stats, setStats] = useState({
  totalReports: 0,
  criticalHotspots: 0,
  byStatus: []
});

useEffect(() => {
  fetch(`${API_BASE_URL}/reports/admin/stats`, {
    headers: { "Authorization": `Bearer ${localStorage.getItem("token")}` }
  })
    .then(res => res.json())
    .then(data => { if (data.success) setStats(data.data); })
    .catch(() => {}); // Keep static numbers if API unavailable
}, []);
  


  return (
    <section className="dashboard-container">

        <section className="firstSection">

            <div 
                onClick={() => navigate("/")}
                className="cursor-pointer hover:opacity-80 transition"
            > 
                <h1>PurePathAI</h1>
            </div>

            <div className="navBar">
                <p><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="currentColor" d="M6 19h3v-6h6v6h3v-9l-6-4.5L6 10zm-2 2V9l8-6l8 6v12h-7v-6h-2v6zm8-8.75"/></svg> </p>
                <h2 className="navItems" onClick={() => navigate("/dashboard")}>Dashboard</h2>
                <h2 className="navItems">Management</h2>
                <h2 className="navItems">Settings</h2>
            </div>

            <div className="icons">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="currentColor" d="m19.485 20.154l-6.262-6.262q-.75.639-1.725.989t-1.96.35q-2.398 0-4.064-1.666Q3.808 11.898 3.808 9.5t1.666-4.064t4.064-1.667t4.065 1.667T15.269 9.5q0 1.042-.369 2.017t-.97 1.668l6.262 6.261zM9.539 14.23q1.99 0 3.36-1.37t1.37-3.361t-1.37-3.36t-3.36-1.37t-3.361 1.37t-1.37 3.36t1.37 3.36t3.36 1.37"/></svg>
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 19v-9a6 6 0 0 1 6-6v0a6 6 0 0 1 6 6v9M6 19h12M6 19H4m14 0h2m-9 3h2"/><circle cx="12" cy="3" r="1"/></g></svg>
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 20 20"><path fill="currentColor" fill-rule="evenodd" d="M10 .5a.5.5 0 0 0-.5.5v18a.5.5 0 0 0 1 0V1a.5.5 0 0 0-.5-.5" clip-rule="evenodd"/></svg>
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="24" viewBox="0 0 20 24"><path fill="currentColor" d="M0 0v512h512V0zm465.5 465.5h-419v-419h418.9v419z"/></svg>
            </div>
        
        </section>

        <section className="secondSection">
            <div className="dashboardHeader" >
                <p className="location">NAIROBI KENYA</p>
                <h1>DASHBOARD</h1>  
            </div>

            <div>
                <button 
                    className="reportWaste"
                    onClick={() => navigate("/report")}
                > 
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 1024 1024"><path fill="currentColor" d="M512 0C229.232 0 0 229.232 0 512c0 282.784 229.232 512 512 512c282.784 0 512-229.216 512-512C1024 229.232 794.784 0 512 0m0 961.008c-247.024 0-448-201.984-448-449.01c0-247.024 200.976-448 448-448s448 200.977 448 448s-200.976 449.01-448 449.01M736 480H544V288c0-17.664-14.336-32-32-32s-32 14.336-32 32v192H288c-17.664 0-32 14.336-32 32s14.336 32 32 32h192v192c0 17.664 14.336 32 32 32s32-14.336 32-32V544h192c17.664 0 32-14.336 32-32s-14.336-32-32-32"/></svg>
                        REPORT WASTE</button>
            </div>

            {/* <div>
                <Link to="/Report-Waste">
                    <button className="reportWaste"> 
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 1024 1024"><path fill="currentColor" d="M512 0C229.232 0 0 229.232 0 512c0 282.784 229.232 512 512 512c282.784 0 512-229.216 512-512C1024 229.232 794.784 0 512 0m0 961.008c-247.024 0-448-201.984-448-449.01c0-247.024 200.976-448 448-448s448 200.977 448 448s-200.976 449.01-448 449.01M736 480H544V288c0-17.664-14.336-32-32-32s-32 14.336-32 32v192H288c-17.664 0-32 14.336-32 32s14.336 32 32 32h192v192c0 17.664 14.336 32 32 32s32-14.336 32-32V544h192c17.664 0 32-14.336 32-32s-14.336-32-32-32"/></svg>
                        REPORT WASTE</button>
                </Link>
            </div>         */}
            
        </section>

        <div className="statsContainer">

            <div className="statCard">
                <div className="statIcon green">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="#00ff66" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"><path d="M11.795 21H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v4m-1 3v4h4"/><path d="M14 18a4 4 0 1 0 8 0a4 4 0 1 0-8 0m1-15v4M7 3v4m-4 4h16"/></g></svg>
                </div>
                <div>
                    <p className="statTitle">ACTIVE REPORTS</p>
                    <h2>{stats.totalReports || 1248}</h2>
                </div>
            </div>

            <div className="statCard">
                <div className="statIcon red">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 40 40"><path fill="red" d="M37.874 37.2H2.132a1.74 1.74 0 0 1-1.501-.866a1.71 1.71 0 0 1-.001-1.729L18.507 3.663a1.728 1.728 0 0 1 2.991-.004l17.833 30.869a1.733 1.733 0 0 1-1.457 2.672M20.001 3.8a.74.74 0 0 0-.628.363L1.496 35.104a.7.7 0 0 0-.001.727a.74.74 0 0 0 .637.369h35.742a.74.74 0 0 0 .732-.73a.8.8 0 0 0-.134-.429L20.634 4.163a.74.74 0 0 0-.633-.363"/><path fill="currentColor" d="M20.002 27.948a.5.5 0 0 1-.5-.5V9.864a.5.5 0 0 1 1 0v17.584a.5.5 0 0 1-.5.5m-.004 3.688a.5.5 0 0 1-.5-.5V29.78a.5.5 0 0 1 1 0v1.355a.5.5 0 0 1-.5.501"/></svg>
                </div>
                <div>
                    <p className="statTitle">HIGH PRIORITY</p>
                    <h2>{stats.criticalHotspots || 14}</h2>
                </div>
            </div>

            <div className="statCard">
                <div className="statIcon blue">
                    <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 16 16"><g fill="none" stroke="blue" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"><path d="m14.25 8.75c-.5 2.5-2.3849 4.85363-5.03069 5.37991-2.64578.5263-5.33066-.7044-6.65903-3.0523-1.32837-2.34784-1.00043-5.28307.81336-7.27989 1.81379-1.99683 4.87636-2.54771 7.37636-1.54771"/><polyline points="5.75 7.75 8.25 10.25 14.25 3.75"/></g></svg>
                </div>
                <div>
                    <p className="statTitle">RESOLVED CASES</p>
                    <h2>{stats.byStatus?.find(s => s.status === 'cleaned')?.count || 842}</h2>
                </div>
            </div>

        </div>

        <div className="dashboard-bottom">

            
                <div className="map-section">
                    <div className="map-header">
                        <h3>Live Status: Nairobi Central</h3>
                        <span className="live-badge">● LIVE UPDATES</span>
                    </div>

                    <div className="map-box">
                        <div className="map-dot dot1"></div>
                        <div className="map-dot dot2"></div>
                        <div className="map-dot dot3"></div>

                        <div className="map-footer">
                            <span>🔴 CBD Critical Zones</span>
                            <button className="expand-view">EXPAND VIEW</button>
                        </div>
                    </div>
                </div>

            
            <div className="activity-section">
                    <div className="activity-header">
                        <h3>Recent Activity</h3>
                        <button
                            className="view-all"
                            onClick={() => setShowAll(!showAll)}
                            >
                            {showAll ? "SHOW LESS" : "VIEW ALL"}
                        </button>
                        {/* <span className="view-all">VIEW ALL</span> */}
                    </div>

            <div className="activity-list">

                <div className="activity-item">
                    <div className="activity-img">
                        <img src="/images/Waste.png" alt="Waste Icon" />
                    </div>
                        <div className="activity-text">
                            <h4>Kenyatta Avenue</h4>
                            <p>12 mins ago</p>
                        </div>
                        <span className="badge pending">PENDING</span>
                    </div>

                    <div className="activity-item">
                        <div className="activity-img">
                        <img src="/images/Waste (1).png" alt="Waste Icon" />
                         </div>
                     
                        <div className="activity-text">
                            <h4>Industrial Area Sec 4</h4>
                            <p>45 mins ago</p>
                        </div>
                        <span className="badge assigned">ASSIGNED</span>
                    </div>
                      

                    <div className="activity-item">
                        <div className="activity-img map">
                           <img src="/images/Waste (2).png" alt="Waste Icon" />
                         </div> 
                        
                        <div className="activity-text">
                            <h4>Westlands Mall</h4>
                            <p>1 hour ago</p>
                        </div>
                        <span className="badge priority">PRIORITY</span>
                    </div>
                    {showAll && (
                        <>
                    <div className="activity-item">
                        <div className="activity-img gray">
                            <img src="/images/Background (6).png" alt="" />
                        </div>
                        <div className="activity-text">
                            <h4>City Market</h4>
                            <p>3 hours ago</p>
                        </div>
                        <span className="badge resolved">RESOLVED</span>
                    </div>
                     </>
                    )}

                </div>
         </div>
         </div>

       

    
    </section>
  )
}