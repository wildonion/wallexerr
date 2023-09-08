




/* 
    converting the String into an static str by leaking the memory of the 
    String to create a longer lifetime allocation for an slice of the String 
*/
pub fn string_to_static_str(s: String) -> &'static str { 
    Box::leak(s.into_boxed_str()) 
}

