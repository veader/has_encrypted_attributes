ActiveRecord::Schema.define(:version => 1) do
  create_table :users, :force => true do |t|
    t.string    'login'
    t.string    'key'
    t.string    'alternate_key'
    t.datetime  'created_at'
    t.datetime  'updated_at'
  end
  
  create_table :secrets, :force => true do |t|
    t.integer   "user_id"
    t.string    'who_killed_jfk'
    t.string    'aliens_at_area_51'
    t.string    'current_president'
    t.datetime  'created_at'
    t.datetime  'updated_at'
  end
  
end
