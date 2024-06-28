Step 1: create .env file  

API_KEY=<your_api_key_here>  
API_SECRET=<your_api_secret_here>  
ENDOR_NAMESPACE=<your_namespace>  

Step 2: run

```
python3 -m venv venv  
source venv/bin/activate  
pip install -r requirements.txt  
```

Step 3:
If you want to download all packages from all projects execute:
```
python3 download_sboms.py 
```
or 

If you want to download only packages from projects with specific tags:
```
python3 download_sboms.py --project_tags="project_tag1, project_tag2"
```


