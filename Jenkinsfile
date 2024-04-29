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
                sh "docker-compose down && docker-compose up"
            }
        }
    }
}
