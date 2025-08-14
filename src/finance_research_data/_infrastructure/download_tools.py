from pathlib import Path
import io, json, requests, pandas as pd
from .auth import get_credential, require_credential
from .._config.settings import USER_AGENT, DEFAULT_TIMEOUT, FRED_BASE

def download_from_url(url, dest:Path|None=None, headers=None, params=None, timeout:float|None=None, method="GET", data=None, stream=False):
    h={"User-Agent":USER_AGENT}; h.update(headers or {})
    r=requests.request(method, url, headers=h, params=params, data=data, timeout=timeout or DEFAULT_TIMEOUT, stream=stream)
    r.raise_for_status()
    if dest:
        dest=Path(dest); dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest,"wb") as f:
            if stream:
                for c in r.iter_content(chunk_size=1024*1024): 
                    if c: f.write(c)
            else: f.write(r.content)
        return dest
    return r.content

def download_from_wrds(sql:str, schema:str|None=None, to_df=True, connect_kwargs:dict|None=None):
    import wrds
    u=get_credential("WRDS_USERNAME"); p=get_credential("WRDS_PASSWORD")
    conn=wrds.Connection(wrds_username=u, wrds_password=p, **(connect_kwargs or {}))
    if schema: conn.schema(schema)
    df=conn.get_sql(sql) if to_df else conn.raw_sql(sql)
    conn.close()
    return df

def download_from_fred(series_id:str, start=None, end=None, api_key:str|None=None, to_df=True):
    key=api_key or require_credential("FRED_API_KEY")
    params={"series_id":series_id,"api_key":key,"file_type":"json"}
    if start: params["observation_start"]=str(start)
    if end: params["observation_end"]=str(end)
    raw=download_from_url(f"{FRED_BASE}/series/observations", headers=None, params=params)
    data=json.loads(raw)
    if not to_df: return data
    obs=data.get("observations",[])
    df=pd.DataFrame(obs)
    if not df.empty:
        df["date"]=pd.to_datetime(df["date"])
        df["value"]=pd.to_numeric(df["value"], errors="coerce")
        df=df[["date","value"]].set_index("date").sort_index()
    return df
