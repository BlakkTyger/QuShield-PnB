## FRONTEND-BACKEND INTEGRATION IS COMPLETELY WRONG AND DOES NOT WORK. ALL BACKEND TESTS PASS BUT NOTHING SHOWS ON FRONTEND. A COMPLETE REFACTOR IS REQUIRED.


There are some major issues with how the backend is communicating with the frontend due to which most of the features are not working:
1. On Quick Scan Page:
    a. There is data leak between users:
        - If I have put google.com for deep scan for user 1, and in the middle of the scan I log out and log in via user 2, then google scan still keeps running and google.com is on the scan bar 
        - If I have put google.com for scan for user 1, and after the scan is complete I log out and log in via user 2, the scan results of google.com are still shown to user 2\
    b. When I run quick scan for google.com, it shows:
        [04/10/26 21:45:27] INFO     quick_scanner Quick scan complete for google.com   
INFO:     172.19.0.4:54862 - "POST /api/v1/scans/quick HTTP/1.1" 200 OK
[04/10/26 21:45:28] DEBUG    crypto_inspector → parse_certificate_chain called  
                    DEBUG    crypto_inspector → parse_certificate called        
                    DEBUG    crypto_inspector Parsed cert: *.google.com         
                             (EC-secp256r1-256)                                 
                    DEBUG    crypto_inspector ← parse_certificate completed in  
                             3.7ms                                              
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,
                             valid=True                                         
                    DEBUG    crypto_inspector ← parse_certificate_chain         
                             completed in 9.1ms                                 
[04/10/26 21:45:28] DEBUG    risk_engine → compute_mosca called                 
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs            
                             Z(pessimistic)=3.0yr → exposed=True                
                    DEBUG    risk_engine ← compute_mosca completed in 2.9ms     
[04/10/26 21:45:28] INFO     quick_scanner Quick scan complete for google.com 

    but frontend does not show anything
    
    c. When I run shallow scan:
    [04/10/26 21:47:18] INFO     shallow_scanner  Phase 1: Subdomain discovery for  
                             google.com                                         
[04/10/26 21:47:42] WARNING  shallow_scanner crt.sh query failed for google.com:
                             [Errno -3] Temporary failure in name resolution    
                    INFO     shallow_scanner CT discovery for google.com: 1     
                             unique subdomains                                  
                    INFO     shallow_scanner CT returned only 1 subdomains,     
                             adding brute-force prefixes                        
                    INFO     shallow_scanner Combined discovery: 57 candidates  
                             for google.com                                     
                    INFO     shallow_scanner  Phase 2: DNS resolution for 57    
                             subdomains                                         
[blakktyger@TygersClaw QuShield-PnB]$ 

And it randomly aborts in the middle along with an abort in the frontend
When the scan is complete, it does not show on the frontend

    d. When I run a deep scan:
        - Cancel scan feature does not cancel the deep scan
        - Telemetry live feed is not visible
        - The box of telemetry live feed is very small for showing logs
        - Status bar and visibility is not comprehensive: 
            - After discovery it does not tell how many assets were discovered
            - After DNS resolution it does not show how many asset's DNS was resolved
            - The scan status bar is not dynamic: It does not update as and when the crypto scan of one asset is complete. It is very discrete, make it more continuous
        - THE LOGS show:
        -                       INFO     scan_events SSE client connected to scan           
                             d286071e-dbe0-40c8-aef1-abda1bc80152               
                    INFO     scan_events SSE generator started for scan         
                             d286071e-dbe0-40c8-aef1-abda1bc80152               
INFO:     172.19.0.4:36558 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:36564 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:36566 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:36578 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:36590 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:43852 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:43854 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:43856 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:43864 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:54464 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
INFO:     172.19.0.4:54468 - "GET /api/v1/scans/d286071e-dbe0-40c8-aef1-abda1bc80152 HTTP/1.1" 200 OK
         and so on..
         
         but the results are not reflected on the frontend
         
        - Cache hits are not working well
        - When deep scan is compelte, it does not show all the results on the dashboard
        
In an essence:
1. Data leak is happening
2. Communication between front end and backend is bad
3. Streaming is not happening well
4. All data that is generated at the backend is not being transferred to the frontend
5. The way the frontend displays data is bad and non intuitive
6. Topology Map is non-interpretable because just label data (4de9b8bfc8f673c8d5c4300a0d6bea063e827d25b1284fc7c828208b0b623804) is visible without any other information or context
7. In the GeoIP map, I can't select the domain. It aggregates all the data of all scanned domains and IPs and displays it. I should have an option to select which domain I want to refer to
8. For dashboard, Assets, CBOM explorer, Rist Intelligence, Compliance, Topology Map, GeoIP Map: I can't select the domain. But I should be able to select the scaned domain and only the data for that specific scan should be displayed

---

FIX ALL THESE ISSUES:
1. Refer to docs/03-FRONTEND.md, docs/04-SYSTEM_ARCHITECTURE.md, docs/PLAN/06-DEVELOPMENT_PLAN.md and docs/PLAN/06f-PLAN_P7_P8.md to understand how frontend is strcutured, how it communicates with the backend etc. 
2. Use the information in these documents to fix the issues
3. Do not change the major UI structure, pages, components etc, just focus on functionality for now
4. After all the analysis, alter PROMPT5.md in order to break this into very specific and granular actionable items. Make it very specific like file or function level changes and divide it into multiple subphases (similar to PROMPT1.md). Refer to this document which making changes and keep checking the things which are complete.
5. Maintain IMPL_SCRATCHPAD.md for reasoning, thinking, planning etc.
6. Before implementing any change and integrating it, first test it out. Only integrate it if it works. 
7. After implementation, run a script for integration test.

At the end of this, the frontend, database and backend should be perfectly integrated.
