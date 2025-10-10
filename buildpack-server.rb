#!/usr/bin/env ruby

require 'sinatra'
require 'zip'
require 'fileutils'

# Enable logging
set :logging, true

# Buildpack file path
BUILDPACK_FILE = './buildpack.tar.gz'

# Function to create the buildpack.tar.gz file
def create_buildpack_file
  # Create tar.gz file using system tar command
  system("tar -czf #{BUILDPACK_FILE} -C buildpack .")
  
  puts "Created buildpack file: #{BUILDPACK_FILE}"
end

# Create the buildpack file once at startup
File.delete(BUILDPACK_FILE) if File.exist?(BUILDPACK_FILE)
create_buildpack_file

get '/*' do
  content_type 'application/gzip'
  attachment 'buildpack.tar.gz'
  
  # Serve the pre-created buildpack file
  File.read(BUILDPACK_FILE)
end

get '/health' do
  content_type 'application/json'
  { status: 'ok', message: 'Buildpack server is running' }.to_json
end

# Start the server
if __FILE__ == $0
  port = ENV['PORT'] || 4567
  puts "Starting buildpack server on http://localhost:#{port}"
  puts "IPv4: http://0.0.0.0:#{port}"
  puts "IPv6: http://[::]:#{port}"
  puts "GET / to download buildpack.tar.gz"
  puts "GET /health for health check"
  
  # Bind to both IPv4 and IPv6
  Sinatra::Application.run!(port: port, host: '::')
end
