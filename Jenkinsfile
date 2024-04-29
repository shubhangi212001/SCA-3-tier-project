pipeline {
    agent any

    environment {
        GITHUB_CREDENTIALS = credentials('github-credentials')
        GITHUB_USERNAME = 'github-credentials.username'
        GITHUB_PASSWORD = 'github-credentials.password'
    }
    
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
                sh "docker build -t shubhangihshindde/bakend-3tier ."
                sh "docker build -t shubhangihshind/frontent ./sca_vite"
            }
        }
        stage('Push') {
            steps {
                echo 'Pushing docker image on Docker Hub'
                sh "docker push shubhangihshindde/bakend-3tier:latest"
                sh "docker push shubhangihshind/frontent:latest"
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
