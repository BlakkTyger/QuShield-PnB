# Quick Scan

While running quick scan, this is on the backend
```
INFO:     127.0.0.1:59428 - "GET /api/v1/auth/me HTTP/1.1" 200 OK
[04/10/26 21:46:29] DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector Parsed cert: pnb.bank.in (RSA-2048) 
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             33.5ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 55.9ms
[04/10/26 21:46:29] DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 8.0ms       
[04/10/26 21:46:29] INFO     quick_scanner Quick scan complete for pnb.bank.in    
INFO:     127.0.0.1:60068 - "POST /api/v1/scans/quick HTTP/1.1" 200 OK
```

# Shallow Scan
```
[04/10/26 21:48:32] INFO     shallow_scanner  Phase 1: Subdomain discovery for    
                             pnb.bank.in
[04/10/26 21:48:36] INFO     shallow_scanner CT discovery for pnb.bank.in: 215    
                             unique subdomains
                    INFO     shallow_scanner  Phase 2: DNS resolution for 215     
                             subdomains
[04/10/26 21:48:39] INFO     shallow_scanner DNS resolution: 149/215 subdomains   
                             are live
                    INFO     shallow_scanner  Phase 3: TLS scan on 10 subdomains  
[04/10/26 21:48:40] DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector Parsed cert: apptrk.pnb.bank.in     
                             (RSA-2048)
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             6.3ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 15.3ms
[04/10/26 21:48:40] DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=2.0yr + Y=7.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 5.9ms       
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector Parsed cert: apitrk.pnb.bank.in     
                             (RSA-2048)
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             6.7ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 16.4ms
                    DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 5.5ms       
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector Parsed cert: ckycr-admin.pnb.bank.in
                             (RSA-2048)
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             5.8ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 14.4ms
                    DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 6.0ms       
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector Parsed cert: apps.pnb.bank.in       
                             (RSA-2048)
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             5.9ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 13.8ms
                    DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=2.0yr + Y=7.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 6.8ms       
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector Parsed cert: ams.pnb.bank.in        
                             (RSA-2048)
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             12.4ms
                    DEBUG    crypto_inspector Parsed cert: aafip.pnb.bank.in      
                             (RSA-2048)
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             11.1ms
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 27.4ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    risk_engine → compute_mosca called
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 28.8ms
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    risk_engine → compute_mosca called
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    risk_engine ← compute_mosca completed in 15.5ms      
                    DEBUG    crypto_inspector Parsed cert: aafiu.pnb.bank.in      
                             (RSA-2048)
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             11.9ms
                    DEBUG    risk_engine ← compute_mosca completed in 18.8ms      
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 27.3ms
                    DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    risk_engine → compute_mosca called
                    DEBUG    crypto_inspector → parse_certificate called
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 12.2ms      
                    DEBUG    crypto_inspector Parsed cert:
                             digidairykcc.pnb.bank.in (RSA-2048)
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             13.0ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 23.5ms
                    DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=1.5yr + Y=5.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 6.6ms       
[04/10/26 21:48:44] DEBUG    crypto_inspector → parse_certificate_chain called    
                    DEBUG    crypto_inspector → parse_certificate called
                    DEBUG    crypto_inspector Parsed cert:
                             applications.pnb.bank.in (RSA-2048)
                    DEBUG    crypto_inspector ← parse_certificate completed in    
                             5.8ms
                    INFO     crypto_inspector Parsed certificate chain: 1 certs,  
                             valid=True
                    DEBUG    crypto_inspector ← parse_certificate_chain completed 
                             in 13.6ms
[04/10/26 21:48:44] DEBUG    risk_engine → compute_mosca called
                    INFO     risk_engine Mosca: X=2.0yr + Y=7.0yr vs
                             Z(pessimistic)=3.0yr → exposed=True
                    DEBUG    risk_engine ← compute_mosca completed in 5.3ms       
[04/10/26 21:48:44] INFO     shallow_scanner Shallow scan complete for
                             pnb.bank.in: 9 assets in 11399ms
INFO:     127.0.0.1:58476 - "POST /api/v1/scans/shallow HTTP/1.1" 200 OK
```

# Deep Scan
```

[04/10/26 21:49:23] ERROR    api Unhandled error: name 'caches' is not defined    
                             ╭──────── Traceback (most recent call last) ────────╮
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\middleware\errors.py:164 in     │
                             │ __call__                                          │
                             │                                                   │
                             │   161 │   │   │   await send(message)             │
                             │   162 │   │                                       │
                             │   163 │   │   try:                                │
                             │ ❱ 164 │   │   │   await self.app(scope, receive,  │
                             │   165 │   │   except Exception as exc:            │
                             │   166 │   │   │   request = Request(scope)        │
                             │   167 │   │   │   if self.debug:                  │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\middleware\cors.py:96 in        │
                             │ __call__                                          │
                             │                                                   │
                             │    93 │   │   │   await response(scope, receive,  │
                             │    94 │   │   │   return                          │
                             │    95 │   │                                       │
                             │ ❱  96 │   │   await self.simple_response(scope, r │
                             │    97 │                                           │
                             │    98 │   def is_allowed_origin(self, origin: str │
                             │    99 │   │   if self.allow_all_origins:          │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\middleware\cors.py:154 in       │
                             │ simple_response                                   │
                             │                                                   │
                             │   151 │                                           │
                             │   152 │   async def simple_response(self, scope:  │
                             │       request_headers: Headers) -> None:          │
                             │   153 │   │   send = functools.partial(self.send, │
                             │ ❱ 154 │   │   await self.app(scope, receive, send │
                             │   155 │                                           │
                             │   156 │   async def send(self, message: Message,  │
                             │       None:                                       │
                             │   157 │   │   if message["type"] != "http.respons │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\middleware\exceptions.py:63 in  │
                             │ __call__                                          │
                             │                                                   │
                             │   60 │   │   else:                                │
                             │   61 │   │   │   conn = WebSocket(scope, receive, │
                             │   62 │   │                                        │
                             │ ❱ 63 │   │   await wrap_app_handling_exceptions(s │
                             │   64 │                                            │
                             │   65 │   async def http_exception(self, request:  │
                             │   66 │   │   assert isinstance(exc, HTTPException │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\_exception_handler.py:53 in     │
                             │ wrapped_app                                       │
                             │                                                   │
                             │   50 │   │   │   │   handler = _lookup_exception_ │
                             │   51 │   │   │                                    │
                             │   52 │   │   │   if handler is None:              │
                             │ ❱ 53 │   │   │   │   raise exc                    │
                             │   54 │   │   │                                    │
                             │   55 │   │   │   if response_started:             │
                             │   56 │   │   │   │   raise RuntimeError("Caught h │
                             │      started.") from exc                          │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\_exception_handler.py:42 in     │
                             │ wrapped_app                                       │
                             │                                                   │
                             │   39 │   │   │   await send(message)              │
                             │   40 │   │                                        │
                             │   41 │   │   try:                                 │
                             │ ❱ 42 │   │   │   await app(scope, receive, sender │
                             │   43 │   │   except Exception as exc:             │
                             │   44 │   │   │   handler = None                   │
                             │   45                                              │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\fastapi\middleware\asyncexitstack.py:18   │
                             │ in __call__                                       │
                             │                                                   │
                             │   15 │   async def __call__(self, scope: Scope, r │
                             │   16 │   │   async with AsyncExitStack() as stack │
                             │   17 │   │   │   scope[self.context_name] = stack │
                             │ ❱ 18 │   │   │   await self.app(scope, receive, s │
                             │   19                                              │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\routing.py:660 in __call__      │
                             │                                                   │
                             │   657 │   │   """                                 │
                             │   658 │   │   The main entry point to the Router  │
                             │   659 │   │   """                                 │
                             │ ❱ 660 │   │   await self.middleware_stack(scope,  │
                             │   661 │                                           │
                             │   662 │   async def app(self, scope: Scope, recei │
                             │   663 │   │   assert scope["type"] in ("http", "w │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\routing.py:680 in app           │
                             │                                                   │
                             │   677 │   │   │   match, child_scope = route.matc │
                             │   678 │   │   │   if match == Match.FULL:         │
                             │   679 │   │   │   │   scope.update(child_scope)   │
                             │ ❱ 680 │   │   │   │   await route.handle(scope, r │
                             │   681 │   │   │   │   return                      │
                             │   682 │   │   │   elif match == Match.PARTIAL and │
                             │   683 │   │   │   │   partial = route             │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\routing.py:276 in handle        │
                             │                                                   │
                             │   273 │   │   │   │   response = PlainTextRespons │
                             │       headers=headers)                            │
                             │   274 │   │   │   await response(scope, receive,  │
                             │   275 │   │   else:                               │
                             │ ❱ 276 │   │   │   await self.app(scope, receive,  │
                             │   277 │                                           │
                             │   278 │   def __eq__(self, other: Any) -> bool:   │
                             │   279 │   │   return (                            │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\fastapi\routing.py:134 in app             │
                             │                                                   │
                             │    131 │   │   │   │   )                          │
                             │    132 │   │                                      │
                             │    133 │   │   # Same as in Starlette             │
                             │ ❱  134 │   │   await wrap_app_handling_exceptions │
                             │    135 │                                          │
                             │    136 │   return app                             │
                             │    137                                            │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\_exception_handler.py:53 in     │
                             │ wrapped_app                                       │
                             │                                                   │
                             │   50 │   │   │   │   handler = _lookup_exception_ │
                             │   51 │   │   │                                    │
                             │   52 │   │   │   if handler is None:              │
                             │ ❱ 53 │   │   │   │   raise exc                    │
                             │   54 │   │   │                                    │
                             │   55 │   │   │   if response_started:             │
                             │   56 │   │   │   │   raise RuntimeError("Caught h │
                             │      started.") from exc                          │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\starlette\_exception_handler.py:42 in     │
                             │ wrapped_app                                       │
                             │                                                   │
                             │   39 │   │   │   await send(message)              │
                             │   40 │   │                                        │
                             │   41 │   │   try:                                 │
                             │ ❱ 42 │   │   │   await app(scope, receive, sender │
                             │   43 │   │   except Exception as exc:             │
                             │   44 │   │   │   handler = None                   │
                             │   45                                              │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\fastapi\routing.py:120 in app             │
                             │                                                   │
                             │    117 │   │   │   │   scope["fastapi_inner_astac │
                             │    118 │   │   │   │   async with AsyncExitStack( │
                             │    119 │   │   │   │   │   scope["fastapi_functio │
                             │ ❱  120 │   │   │   │   │   response = await f(req │
                             │    121 │   │   │   │   await response(scope, rece │
                             │    122 │   │   │   │   # Continues customization  │
                             │    123 │   │   │   │   response_awaited = True    │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\fastapi\routing.py:674 in app             │
                             │                                                   │
                             │    671 │   │   │   │   response = actual_response │
                             │    672 │   │   │   │   response.headers.raw.exten │
                             │    673 │   │   │   else:                          │
                             │ ❱  674 │   │   │   │   raw_response = await run_e │
                             │    675 │   │   │   │   │   dependant=dependant,   │
                             │    676 │   │   │   │   │   values=solved_result.v │
                             │    677 │   │   │   │   │   is_coroutine=is_corout │
                             │                                                   │
                             │ C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-p │
                             │ ackages\fastapi\routing.py:328 in                 │
                             │ run_endpoint_function                             │
                             │                                                   │
                             │    325 │   assert dependant.call is not None, "de │
                             │    326 │                                          │
                             │    327 │   if is_coroutine:                       │
                             │ ❱  328 │   │   return await dependant.call(**valu │
                             │    329 │   else:                                  │
                             │    330 │   │   return await run_in_threadpool(dep │
                             │    331                                            │
                             │                                                   │
                             │ C:\Users\sgpan\QuShield-PnB\backend\app\api\v1\sc │
                             │ ans.py:45 in create_scan                          │
                             │                                                   │
                             │    42                                             │
                             │    43 @router.post("", response_model=ScanRespons │
                             │    44 async def create_scan(request: ScanRequest, │
                             │       Depends(get_current_user), db: Session = De │
                             │ ❱  45 │   for cache in caches:                    │
                             │    46 │   │   scan_job = db.query(ScanJob).filter │
                             │    47 │   │   if not scan_job or scan_job.status  │
                             │       "completed" and getattr(scan_job, "total_as │
                             │    48 │   │   │   db.delete(cache)                │
                             ╰───────────────────────────────────────────────────╯
                             NameError: name 'caches' is not defined
INFO:     127.0.0.1:64852 - "POST /api/v1/scans HTTP/1.1" 500 Internal Server Error
ERROR:    Exception in ASGI application
Traceback (most recent call last):
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\uvicorn\protocols\http\httptools_impl.py", line 420, in run_asgi
    result = await app(  # type: ignore[func-returns-value]
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\uvicorn\middleware\proxy_headers.py", line 60, in __call__
    return await self.app(scope, receive, send)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\fastapi\applications.py", line 1163, in __call__
    await super().__call__(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\applications.py", line 90, in __call__
    await self.middleware_stack(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\middleware\errors.py", line 186, in __call__
    raise exc
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\middleware\errors.py", line 164, in __call__
    await self.app(scope, receive, _send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\middleware\cors.py", line 96, in __call__
    await self.simple_response(scope, receive, send, request_headers=headers)     
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\middleware\cors.py", line 154, in simple_response
    await self.app(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\middleware\exceptions.py", line 63, in __call__
    await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)      
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\_exception_handler.py", line 53, in wrapped_app
    raise exc
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\fastapi\middleware\asyncexitstack.py", line 18, in __call__
    await self.app(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\routing.py", line 660, in __call__
    await self.middleware_stack(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\routing.py", line 680, in app
    await route.handle(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\routing.py", line 276, in handle
    await self.app(scope, receive, send)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\fastapi\routing.py", line 134, in app
    await wrap_app_handling_exceptions(app, request)(scope, receive, send)        
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\_exception_handler.py", line 53, in wrapped_app
    raise exc
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\starlette\_exception_handler.py", line 42, in wrapped_app
    await app(scope, receive, sender)
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\fastapi\routing.py", line 120, in app
    response = await f(request)
               ^^^^^^^^^^^^^^^^
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\fastapi\routing.py", line 674, in app
    raw_response = await run_endpoint_function(
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\sgpan\miniconda3\envs\gtk_env\Lib\site-packages\fastapi\routing.py", line 328, in run_endpoint_function
    return await dependant.call(**values)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\sgpan\QuShield-PnB\backend\app\api\v1\scans.py", line 45, in create_scan
    for cache in caches:
                 ^^^^^^
NameError: name 'caches' is not defined
```
