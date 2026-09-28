Zip::File.open(path) do |z|
  puts z.entries.length
end
