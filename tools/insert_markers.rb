#!/usr/bin/env ruby
# frozen_string_literal: true

# Inserts markers in every control file:
# after the last 'tag ...' in each control block, before the block's final 'end'.
# Idempotent: skips if markers already present in that control.
#
# Usage: ruby tools/insert_markers.rb

DIR = File.join(__dir__, '..', 'controls')

MARKER_BEGIN = "# --- Begin Custom Code ---"
MARKER_END   = "# --- End Custom Code ---"

Dir.glob(File.join(DIR, '*.rb')).sort.each do |path|
  content = File.read(path)
  original = content.dup

  # Process each control block separately
  content = content.gsub(/(^\s*control\s+['"][^'"]+['"].*?\n)(.*?)(^\s*end\s*$)/m) do |block|
    header = Regexp.last_match(1)
    body   = Regexp.last_match(2)
    ender  = Regexp.last_match(3)

    # Skip if already present
    next block if body.include?(MARKER_BEGIN) && body.include?(MARKER_END)

    # Find the last 'tag ...' occurrence in body
    last_tag_idx = nil
    body.scan(/^\s*tag\b.*$/) { last_tag_idx = Regexp.last_match.begin(0) }

    # If no tag lines found, place markers just before end
    if last_tag_idx.nil?
      new_body = body.rstrip + "\n#{MARKER_BEGIN}\n#{MARKER_END}\n"
      "#{header}#{new_body}#{ender}"
    else
      # Insert markers immediately after the last tag line
      insertion_point = last_tag_idx
      # Advance to the end of that line
      insertion_point = body.index(/\n/, insertion_point) || body.length
      prefix = body[0..insertion_point]
      suffix = body[insertion_point+1..] || ""
      new_body = "#{prefix}#{MARKER_BEGIN}\n#{MARKER_END}\n#{suffix}"
      "#{header}#{new_body}#{ender}"
    end
  end

  if content != original
    File.write(path, content)
    puts "Updated #{path}"
  else
    puts "No changes for #{path}"
  end
end
