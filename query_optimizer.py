class QueryOptimizer:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def get_user_dashboard_data(self, user_id, role, department, selected_dept=""):
        """Optimized query for dashboard data"""
        cache_key = f"dashboard:{user_id}:{selected_dept}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        with self.db.get_connection() as conn:
            with conn.cursor() as cursor:
                # Get forms based on role with single optimized query
                if role in ['admin', 'super_admin']:
                    query = """
                        SELECT f.*, u.name as creator_name, u.department as creator_department,
                               (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count,
                               (SELECT COUNT(*) FROM assignments WHERE form_id = f.id) as assignment_count
                        FROM forms f 
                        JOIN users u ON f.created_by = u.id 
                        WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    """
                    params = []
                    if selected_dept:
                        query += " AND f.department = %s"
                        params.append(selected_dept)
                    query += " ORDER BY f.created_at DESC LIMIT 50"
                    
                    cursor.execute(query, params)
                    forms = cursor.fetchall()
                
                elif role == 'teacher':
                    query = """
                        SELECT f.*, u.name as creator_name,
                               (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count
                        FROM forms f 
                        JOIN users u ON f.created_by = u.id 
                        WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                        AND f.department = %s
                        ORDER BY f.created_at DESC LIMIT 50
                    """
                    cursor.execute(query, (department,))
                    forms = cursor.fetchall()
                
                else:  # student
                    query = """
                        SELECT f.*, u.name as creator_name,
                               (SELECT status FROM form_requests WHERE form_id = f.id AND student_id = %s) as request_status,
                               (SELECT 1 FROM assignments WHERE form_id = f.id AND student_id = %s) as is_assigned,
                               (SELECT 1 FROM responses WHERE form_id = f.id AND student_id = %s) as has_submitted,
                               (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count
                        FROM forms f 
                        JOIN users u ON f.created_by = u.id 
                        WHERE f.department = %s 
                        AND f.form_type = 'open'
                        AND (f.is_student_submission = FALSE OR f.review_status = 'approved')
                        ORDER BY f.created_at DESC LIMIT 50
                    """
                    cursor.execute(query, (user_id, user_id, user_id, department))
                    forms = cursor.fetchall()
                
                # Get assigned forms for students
                assigned_forms = []
                if role == 'student':
                    cursor.execute("""
                        SELECT f.*, a.due_date, a.is_completed 
                        FROM forms f
                        JOIN assignments a ON f.id = a.form_id
                        WHERE a.student_id = %s AND f.review_status = 'approved'
                        LIMIT 20
                    """, (user_id,))
                    assigned_forms = cursor.fetchall()
                
                # Get pending counts
                pending_counts = {}
                if role in ['teacher', 'admin', 'super_admin']:
                    if role in ['admin', 'super_admin']:
                        cursor.execute("SELECT COUNT(*) as count FROM form_requests WHERE status = 'pending'")
                    else:
                        cursor.execute("""
                            SELECT COUNT(*) as count 
                            FROM form_requests fr
                            JOIN forms f ON fr.form_id = f.id
                            WHERE f.created_by = %s AND fr.status = 'pending'
                        """, (user_id,))
                    pending_counts['requests'] = cursor.fetchone()['count']
                    
                    # Get pending reviews
                    if role in ['admin', 'super_admin']:
                        if selected_dept:
                            cursor.execute("""
                                SELECT COUNT(*) as count FROM forms 
                                WHERE is_student_submission = TRUE 
                                AND review_status = 'pending'
                                AND department = %s
                            """, (selected_dept,))
                        else:
                            cursor.execute("""
                                SELECT COUNT(*) as count FROM forms 
                                WHERE is_student_submission = TRUE 
                                AND review_status = 'pending'
                            """)
                    else:
                        cursor.execute("""
                            SELECT COUNT(*) as count FROM forms 
                            WHERE is_student_submission = TRUE 
                            AND review_status = 'pending'
                            AND department = %s
                        """, (department,))
                    pending_counts['reviews'] = cursor.fetchone()['count']
                
                result = {
                    'forms': forms,
                    'assigned_forms': assigned_forms,
                    'pending_counts': pending_counts
                }
                
                # Cache for 30 seconds
                cache.set(cache_key, result)
                return result
    
    def get_user_notifications_fast(self, user_id, limit=20):
        """Fast notification retrieval"""
        cache_key = CacheKeys.notifications(user_id)
        
        def fetch_notifications():
            with self.db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT * FROM notifications 
                        WHERE user_id = %s 
                        ORDER BY created_at DESC 
                        LIMIT %s
                    """, (user_id, limit))
                    return cursor.fetchall()
        
        return cache.get_or_set(cache_key, fetch_notifications)
    
    def get_unread_count_fast(self, user_id):
        """Fast unread count retrieval"""
        cache_key = CacheKeys.unread_count(user_id)
        
        def fetch_count():
            with self.db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT COUNT(*) as count FROM notifications 
                        WHERE user_id = %s AND is_read = FALSE
                    """, (user_id,))
                    return cursor.fetchone()['count']
        
        return cache.get_or_set(cache_key, fetch_count)

# Global query optimizer instance
query_optimizer = QueryOptimizer(db_manager)
