#!/usr/bin/env ruby

require 'sinatra'
require 'zip'
require 'fileutils'
require 'openssl'
require 'base64'
require 'json'

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

get '/buildpack/*' do |path|
  content_type 'application/gzip'
  attachment 'buildpack.tar.gz'
  
  # Serve the pre-created buildpack file
  File.read(BUILDPACK_FILE)
end

get '/health' do
  content_type 'application/json'
  { status: 'ok', message: 'Buildpack server is running' }.to_json
end

# /echo prints headers, body, and request info
get '/echo' do
  content_type 'application/json'
  response = { headers: request.env, body: request.body.read, request: request.inspect }.to_json
  puts response
  response
end

def decrypt_heroku_token(encrypted_data)
  client_secret = ENV['HEROKU_OAUTH_SECRET']
  return unless client_secret
  ciphertext = Base64.urlsafe_decode64(encrypted_data)
  key        = OpenSSL::Digest::SHA256.digest(client_secret)
  
  # Extract nonce and authentication tag
  nonce      = ciphertext[0, 12]
  tag        = ciphertext[-16..-1]
  ciphertext = ciphertext[12...-16]
  
  # Decrypt
  cipher          = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key      = key
  cipher.iv       = nonce
  cipher.auth_tag = tag
  
  decrypted = cipher.update(ciphertext) + cipher.final
  JSON.parse(decrypted)
end

get '/admin' do
  result = "Hi admin"
  begin
    encrypted_token = request.cookies['heroku_oauth_token']
    token_data = decrypt_heroku_token(encrypted_token)
    result += " - #{token_data['email']}"
  rescue => e
    puts "Error decrypting heroku token: #{e.message}"
  end
  
  result
end

# Start the server
if __FILE__ == $0
  port = ENV['PORT'] || '4567'
  port = port.to_i
  puts "Starting buildpack server on http://localhost:#{port}"
  puts "IPv4: http://0.0.0.0:#{port}"
  puts "IPv6: http://[::]:#{port}"
  puts "GET / to download buildpack.tar.gz"
  puts "GET /health for health check"
  
  # Bind to both IPv4 and IPv6
  Sinatra::Application.run!(port: port, host: '::')
end
