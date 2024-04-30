import requests,os
import json
import re
import time
import xml.etree.ElementTree as ET
from fastapi import FastAPI, File, UploadFile
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
import shutil
import xml.etree.ElementTree as ET
import ast
from fastapi import Depends
import models
from db import get_db
from sqlalchemy.orm import Session



path = os.getcwd()
app = FastAPI()
api_key = "334a1e24-fa44-43f2-b526-16b749527623"
api_key2 ="5f731b5c-ce73-47bb-9b6e-11e3702575dd" 
products = []
new_versions = []
pcpe = []

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*']
)



@app.post("/")
async def upload_file(file: UploadFile = File(...),db: Session = Depends(get_db)):
    file_path = os.path.join(file.filename)
    print(path)
    # Save the uploaded file to the "uploads" directory
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # return {"filename": file.filename}



 

    fname= file.filename
    print(fname)

 

    final_path = path+"//"+fname
    print(final_path)
    # jsondata = parse_file(final_path)

 
    file_extension = os.path.splitext(final_path)[1]



    if file_extension == ".txt": 

        with open(file_path, 'r') as file:
            content = file.read()
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line:
                product, version = re.split(r'==|>=',line)
                print("Sleeping for 1 seconds")
                time.sleep(1)
                url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={product}"
                headers = {
                    "Authorization": "Bearer " + api_key,
                    "Content-Type": "api_keyplication/json"
                }
                
                retry_count = 0
                max_retries = 3
                retry_delay = 5
                
                while retry_count < max_retries:
                    response = make_api_call(url, headers)
                    if response is not None:
                        break
                    print("Retrying after a delay...")
                    time.sleep(retry_delay)
                    retry_count += 1

                if response is None:
                    print(f"Max retries exceeded for URL: {url}")
                    continue

                try:
                    data = response.json()
                    print("1")
                    # print(data)
                except json.JSONDecodeError as e:
                    print("JSON decoding error:", e)
                    print("2")
                    print("Response content:", response.content)
                    continue

                if data['totalResults'] == 0:
                    continue

                first_cpe = data['products'][0]['cpe']['cpeName']
                print("first_cpe",first_cpe)
                pcpe.append(first_cpe)
                products.append(product.strip())
                new_versions.append(version.strip())

    elif file_extension == ".xml":
    #     print("The file extension is .txt")
    # else:
    #     print("The file extension is not .txt")

        tree = ET.parse(file_path)
        root = tree.getroot()

        # Define the XML namespace
        namespace = {'ns': 'http://maven.apache.org/POM/4.0.0'}

        # Find all dependencies
        dependencies = root.findall('.//ns:dependency', namespace)

        # Extract artifactIds and versions
        artifact_ids = []
        

        for dependency in dependencies:

            artifact_element = dependency.find('ns:artifactId', namespace)
            version_element = dependency.find('ns:version', namespace)

            # Check if artifactId and version elements exist
            if artifact_element is not None and version_element is not None:
                artifact_id = artifact_element.text
                version = version_element.text
                print("Sleeping for 1 seconds")
                time.sleep(1)
                url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={artifact_id}"
                headers = {
                    "Authorization": "Bearer " + api_key,
                    "Content-Type": "api_keyplication/json"
                }
                
                retry_count = 0
                max_retries = 3
                retry_delay = 5
                
                while retry_count < max_retries:
                    response = make_api_call(url, headers)
                    if response is not None:
                        break
                    print("Retrying after a delay...")
                    time.sleep(retry_delay)
                    retry_count += 1

                if response is None:
                    print(f"Max retries exceeded for URL: {url}")
                    continue

                try:
                    data = response.json()
                    print("1")
                    # print(data)
                except json.JSONDecodeError as e:
                    print("JSON decoding error:", e)
                    print("2")
                    print("Response content:", response.content)
                    continue

                if data['totalResults'] == 0:
                    continue
                #first_cpe = data['products'][1]['cpe']['cpeName']
                # first_cpe = data['result']['cpes'][0]['cpe23Uri']
                # pcpe.append(first_cpe)
                # # products.append(product.strip())
                # # new_versions.append(version.strip())

                # artifact_ids.append(artifact_id)
                # versions.append(version)
                # print("Dependencies:", artifact_ids)
                # print("Versions:", versions)

                first_cpe = data['products'][0]['cpe']['cpeName']
                # print("first_cpe",first_cpe)
                # pcpe.append(first_cpe)
                # products.append(product.strip())
                # new_versions.append(version.strip())

                # pcpe.append(first_cpe)
                # products.append(product.strip())
                # new_versions.append(version.strip())
                pcpe.append(first_cpe)
                artifact_ids.append(artifact_id)
                new_versions.append(version)
                print("Dependencies:", artifact_ids)
                print("Version:", new_versions)          


    elif file_extension == ".json":

        with open(file_path) as file:

            data = json.load(file)

        # Extract the dependencies and their versions
        dependencies = data['dependencies']
        dependency_names = list(dependencies.keys())


        for dependency, version in dependencies.items():
            print(f"{dependency}: {version}")   
            print("Sleeping for 1 seconds")
            time.sleep(1)
            #url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={product}"
            url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={dependency}"
            headers = {
                "Authorization": "Bearer " + api_key,
                "Content-Type": "api_keyplication/json"
            }
            
            retry_count = 0
            max_retries = 3
            retry_delay = 5
            
            while retry_count < max_retries:
                response = make_api_call(url, headers)
                if response is not None:
                    break
                print("Retrying after a delay...")
                time.sleep(retry_delay)
                retry_count += 1

            if response is None:
                print(f"Max retries exceeded for URL: {url}")
                continue

            try:
                data = response.json()
                print("1")
                # print(data)
            except json.JSONDecodeError as e:
                print("JSON decoding error:", e)
                print("2")
                print("Response content:", response.content)
                continue

            if data['totalResults'] == 0:
                continue

            first_cpe = data['products'][0]['cpe']['cpeName']
            pcpe.append(first_cpe)
            version = version.replace('^', '').replace('~', '')
            new_versions.append(version)


    else:
        print("No file found")


    # with open(file_path, 'r') as file:
    #     content = file.read()

    # lines = content.split('\n')
    # for line in lines:
    #     line = line.strip()
    #     if line:
    #         product, version = line.split('==')
    #         url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={product}"
    #         headers = {
    #             "Authorization": "Bearer " + api_key,
    #             "Content-Type": "application/json"
    #         }
    #         response = requests.get(url, headers=headers)
    #         print(response.status_code)
    #         if response.status_code == 503:
    #             print("Sleeping for 30 seconds")
    #             time.sleep(2)
    #         else:
    #             print("Sleeping for 20 seconds")
    #             time.sleep(2)

    #         try:
    #             data = response.json()
    #             print("1")
    #         except json.JSONDecodeError as e:
    #             print("JSON decoding error:", e)
    #             print("2")
    #             print("Response content:", response.content)
    #             continue

    #         if data['totalResults'] == 0:
    #             continue

            
    #         first_cpe = data['products'][0]['cpe']['cpeName']
    #         print("first_cpe",first_cpe)
    #         pcpe.append(first_cpe)
    #         products.append(product.strip())
    #         new_versions.append(version.strip())

    # return products, new_versions


# file_path = "/home/prasad/pysafebrowsing/requirements.txt"  # Replace with the actual path to your file
# products, new_versions = parse_file(file_path)
# modified_lists = []
# print("Products:", products)
# print("New Versions:", new_versions)
# print(modified_lists)

    

    print("Products:", products)
    print("New Versions:", new_versions)
    print("pcpe:", pcpe)

 

    modified_lists = []

    for i in range(len(pcpe)):
        original_string = pcpe[i]
        version = new_versions[i]

        # Split the original string into its components
        parts = original_string.split(':')

        # Replace the version number
        parts[5] = version

        # Join the parts back into a single string
        converted_string = ':'.join(parts)

        parts = converted_string.split(':')

        # Remove the last 7 elements
        modified_parts = parts[:-7]

        # Join the modified parts back into a single string
        modified_string = ':'.join(modified_parts)

        modified_lists.append(modified_string)

    print(modified_lists)


    test2= products.clear()
    print(test2)

    test3= new_versions.clear()
    print(test3)

    test4= pcpe.clear()
    print(test4)

    cve_list = []
    cve_info_list = []
    extracted_data_list = []
    for modified_list in modified_lists:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={modified_list}"
        headers = {
            "Authorization": "Bearer " + api_key2,
            "Content-Type": "application/json"
        }
        retry_count = 0
        max_retries = 3
        retry_delay = 5
        
        while retry_count < max_retries:
            response = make_api_call(url, headers)
            if response is not None:
                break
            print("Retrying after a delay...")
            time.sleep(retry_delay)
            retry_count += 1

        if response is None:
            print(f"Max retries exceeded for URL: {url}")
            continue

        try:
            data = response.json()
            data1 = json.dumps(data)
        except json.JSONDecodeError as e:
            print("JSON decoding error:", e)
            print("Response content:", response.content)
            continue

        if response.status_code == 200:

            data3=json.loads(data1)
            # print("data3",data3)
            num_cves = data3.get("totalResults", 0)
            print("\n")
            #print(data1)
            # CVE.append(data1)
            # print(CVE)
            print("\n")
            print(f"Number of CVEs found: {num_cves}")

            data = json.loads(data1)

            # cve_list = data.get("vulnerabilities", [])
            # cve_ids = [cve_entry["cve"]["id"] for cve_entry in cve_list]

            # # Print CVE IDs
            # for cve_id in cve_ids:
            #     print("CVE ID:", cve_id)


            def extract_fields(cve_item):
                cve_ids= cve_item["cve"]["id"]
                cve_descrip= cve_item['cve']['descriptions'][0]['value']
                # base_score = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                # base_severity = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                # Try to extract from cvssMetricV31
                
                # try:
                #     base_score = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                #     base_severity = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                # except KeyError:
                #     base_score = None
                #     base_severity = None

                # # If cvssMetricV31 is not present, try to extract from cvssMetricV2
                # if base_score is None or base_severity is None:
                #     try:
                #         base_score = cve_item['cve']['metrics']['cvssMetricV2'][0]['cvssData']['impactScore']
                #         base_severity = cve_item['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                #     except KeyError:
                #         base_score = None
                #         base_severity = None

                base_score = None
                base_severity = None

                # Try to extract from cvssMetricV31, if available
                if 'cvssMetricV31' in cve_item['cve']['metrics']:
                    cvss_metric = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']
                    base_score = cvss_metric.get('baseScore')
                    base_severity = cvss_metric.get('baseSeverity')

                # If cvssMetricV31 is not available, try to extract from cvssMetricV2
                if base_score is None or base_severity is None:
                    if 'cvssMetricV2' in cve_item['cve']['metrics']:
                        cvss_metric = cve_item['cve']['metrics']['cvssMetricV2'][0]['cvssData']
                        cvss_metric1 = cve_item['cve']['metrics']['cvssMetricV2'][0]
                        base_score = cvss_metric.get('baseScore')
                        base_severity = cvss_metric1.get('baseSeverity')

                weakness_description = cve_item['cve']['weaknesses'][0]['description'][0]['value']
                references = cve_item['cve']['references']
                configurations = cve_item['cve']['configurations'][0]['nodes']
                return cve_ids, cve_descrip,base_score,base_severity,weakness_description,references,configurations

            for cve_item in data.get("vulnerabilities", []):
                cve_ids,cve_descrip,base_score,base_severity,weakness_description,references,configurations = extract_fields(cve_item)
                # print("cve_ids",cve_ids)
                # print("cve_descrip",cve_descrip)
                # print("base_score",base_score)
                # print("base_severity",base_severity)
                # print("weakness_description",weakness_description)
                # print("references",references)
                # print("configurations",configurations)

                reference_url = []
                for reference in references:
                    # print("0000000000",reference['url'])
                    reference_url.append(reference['url'])
                # print("reference_url",reference_url)


                cpe_match_fields = []
                product_name = []
                for config in configurations:
                    # print("config",config)
                    cpe_match = config['cpeMatch']
                    # print("cpe_match",cpe_match)
                    for cpe in cpe_match:
                        # print("cpe",cpe)
                        cpe_fields = {}
                        # cpe_fields['cpe23Uri'] = cpe['cpe23Uri']
                        if 'versionEndExcluding' in cpe:
                            cpe_fields['versionEndExcluding'] = cpe['versionEndExcluding']
                        if 'versionEndIncluding' in cpe:
                            cpe_fields['versionEndIncluding'] = cpe['versionEndIncluding']
                        # print("cpe_fields",cpe_fields)
                        cpe_match_fields.append(cpe_fields)

                        # if 'cpeName' in cpe_fields:
                        #     cpe_parts = cpe_fields['cpeName'].split(':')
                        #     if len(cpe_parts) >= 5:
                        #         print("%%%%%%%%%%%%",cpe_parts[4])
                        #         print(type(cpe_parts[4]))
                        #         product_name.append(cpe_parts[4])

                        if 'criteria' in cpe:
                            cpe_parts = cpe['criteria'].split(':')
                            if len(cpe_parts) >= 5:
                                # print("%%%%%%%%%%%%",cpe_parts[4])
                                # print(type(cpe_parts[4]))
                                product_name.append(cpe_parts[4])


                if weakness_description=="NVD-CWE-Other":


                    print(type(weakness_description))
                    print("222222") 
                    # result_string="None"
                    print("1")
                    cwe_id= weakness_description
                    cwe=db.query(models.SCA.name).filter(models.SCA.cwe_id==cwe_id).first()
                    print("2")
                    print('cwe',cwe)
                    print(type(cwe))
                    cwe2= str(cwe)
                    # cwe3= tuple(cwe2)
                    # print('cwe3',cwe3)
                    # print(type(cwe3))
                    result_tuple = ast.literal_eval(cwe2)

                    # Extract the first element from the tuple, which is the desired string
                    result_string = result_tuple[0]

                    print("*************",result_string)

                    extracted_data = {
                        "cve_id": cve_ids,
                        "vulnerability": result_string,
                        "description": cve_descrip,
                        "product_name": product_name[0],
                        "problemtype": weakness_description,
                        "configurations": cpe_match_fields,
                        "references":reference_url,
                        "impact": {
                            "base_score": base_score,
                            "base_severity": base_severity
                        }
                    }

                    extracted_data_list.append(extracted_data)

                elif weakness_description=="NVD-CWE-noinfo":


                    print(type(weakness_description))
                    print("222222") 
                    # result_string="None"
                    print("1")
                    cwe_id= weakness_description
                    cwe=db.query(models.SCA.name).filter(models.SCA.cwe_id==cwe_id).first()
                    print("2")
                    print('cwe',cwe)
                    print(type(cwe))
                    cwe2= str(cwe)
                    # cwe3= tuple(cwe2)
                    # print('cwe3',cwe3)
                    # print(type(cwe3))
                    result_tuple = ast.literal_eval(cwe2)

                    # Extract the first element from the tuple, which is the desired string
                    result_string = result_tuple[0]

                    print("*************",result_string)

                    extracted_data = {
                        "cve_id": cve_ids,
                        "vulnerability": result_string,
                        "description": cve_descrip,
                        "product_name": product_name[0],
                        "problemtype": weakness_description,
                        "configurations": cpe_match_fields,
                        "references":reference_url,
                        "impact": {
                            "base_score": base_score,
                            "base_severity": base_severity
                        }
                    }

                    extracted_data_list.append(extracted_data)

                else:
                    cwe_id= weakness_description
                    cwe_id=cwe_id.split('-')
                    cwe_id=cwe_id[1]
                    cwe=db.query(models.SCA.name).filter(models.SCA.cwe_id==cwe_id).first()
                    print('cwe',cwe)
                    print(type(cwe))
                    cwe2= str(cwe)
                    # cwe3= tuple(cwe2)
                    # print('cwe3',cwe3)
                    # print(type(cwe3))
                    result_tuple = ast.literal_eval(cwe2)

                    # Extract the first element from the tuple, which is the desired string
                    result_string = result_tuple[0]

                    print("*************",result_string)

                    # Creating a dictionary to store extracted data for this CVE
                    extracted_data = {
                        "cve_id": cve_ids,
                        "vulnerability": result_string,
                        "description": cve_descrip,
                        "product_name": product_name[0],
                        "problemtype": weakness_description,
                        "configurations": cpe_match_fields,
                        "references":reference_url,
                        "impact": {
                            "base_score": base_score,
                            "base_severity": base_severity
                        }
                    }

     

                    # Append the extracted data to the list
                    extracted_data_list.append(extracted_data)

        else:
            print("Error occurred while retrieving CVE information.")

    


    count= len(extracted_data_list)
    count2={"total_cve":count}
    extracted_data_list.insert(0,count2)

    print("count######",count)
    output_json = json.dumps(extracted_data_list, indent=2)
    data1 = json.loads(output_json)
    print("type data1",type(data1))



        # Print the JSON data
    return data1




def make_api_call(url, headers):
    try:
        response = requests.get(url, headers=headers)
        print(response.status_code)
        if response.status_code == 200:
            return response
        elif response.status_code == 503:
            raise Exception("503 Forbidden")
        else:
            raise Exception(f"Unexpected status code: {response.status_code}")
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return None

 

if __name__ == '__main__':
    uvicorn.run("main:app", host='172.16.22.122', port=30300, log_level="error", reload = True)
    print("running")