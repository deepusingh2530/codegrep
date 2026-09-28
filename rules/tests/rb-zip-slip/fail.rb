Zip::File.open(path) do |z|
  entry.extract(dest)
end
