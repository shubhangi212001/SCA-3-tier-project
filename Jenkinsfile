pipeline {
    agent any
    
    stages {
        stage('Workspace Cleaning'){
            steps{
                cleanWs()
            }
        }
        stage("Code"){
            steps{
                git url: "https://github.com/shubhangi212001/SCA-3-tier-project.git", branch: "main"
            }
        }
         stage('Deploy') {
            steps {
                echo 'Deploying the container'
                sh "docker-compose down"
            }
        }
        stage('Build') {
            steps {
                echo 'Building the image'
                sh "docker build -t bakend-3tier ."
                sh "docker build -f ./sca_vite/Dockerfile -t frontend-3tier ."
            }
        }
        stage('Push') {
            steps {
                echo 'Pushing docker image on Docker Hub'
                withCredentials([usernamePassword(credentialsId: 'DOCKERHUB', passwordVariable: 'dockerHubpass', usernameVariable: 'dockerHubuser')]) {
                    //sh "docker tag bakend-3tier ${env.dockerHubuser}/bakend-3tier:latest"
                    //sh "docker tag frontend-3tier ${env.dockerHubuser}/frontend-3tier:latest"
                    sh "docker login -u ${env.dockerHubuser} -p ${env.dockerHubpass}"
                    sh "docker push ${env.dockerHubuser}/bakend-3tier:latest"
                    sh "docker push ${env.dockerHubuser}/frontend-3tier:latest"
                }
            }
        }
       
        stage('Deploy to Kubernetes'){
            steps{
                script{
                    
                        withKubeConfig(caCertificate: '', clusterName: '', contextName: '', credentialsId: 'k8s_122', namespace: '', restrictKubeConfigAccess: false, serverUrl: '') {
                                sh 'kubectl delete -f deployment.yml'
                                sh 'kubectl delete -f service.yml'
                                sh 'kubectl apply -f deployment.yml'
                                sh 'kubectl apply -f service.yml'
                                sh 'kubectl get svc'
                                sh 'kubectl get all'
                        }   
                    
                }    
            }
        }        
    }
}
